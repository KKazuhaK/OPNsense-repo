<?php
/* Exercise the unmodified integration CLI against isolated XML fixtures. */
function ownership_check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function ownership_remove(string $path): void
{
    if (is_dir($path) && !is_link($path)) {
        foreach (scandir($path) as $name) {
            if ($name !== '.' && $name !== '..') {
                ownership_remove($path . '/' . $name);
            }
        }
        rmdir($path);
    } else {
        unlink($path);
    }
}

function ownership_run(string $helper, string $root, string $action): void
{
    $process = proc_open([PHP_BINARY, $helper, $action, '1'],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes,
        null, array_merge(getenv(), ['OS_MIHOMO_ROOT' => $root]));
    ownership_check(is_resource($process), 'Unable to launch the isolated integration helper.');
    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]);
    $error = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    ownership_check(proc_close($process) === 0,
        'The isolated integration helper failed during ' . $action . ': ' . $output . $error);
}

function ownership_document(string $path): DOMXPath
{
    $doc = new DOMDocument();
    ownership_check($doc->load($path, LIBXML_NONET), 'Unable to read the isolated XML fixture.');
    return new DOMXPath($doc);
}

function ownership_seed(string $root, string $xml): void
{
    file_put_contents($root . '/conf/config.xml', $xml);
    chmod($root . '/conf/config.xml', 0600);
    file_put_contents($root . '/var/db/os-mihomo/tun-state.json',
        json_encode(['interface' => 'opt9', 'created_interface' => true, 'created_rule' => true], JSON_THROW_ON_ERROR));
    chmod($root . '/var/db/os-mihomo/tun-state.json', 0600);
}

$helper = $argv[1] ?? dirname(__DIR__, 2) . '/src/usr/local/opnsense/scripts/mihomo/setup_unbound.php';
ownership_check(is_file($helper), 'The shipped integration helper was not found.');
$directory = sys_get_temp_dir() . '/mihomo-tun-ownership-' . bin2hex(random_bytes(8));
mkdir($directory, 0700);
mkdir($directory . '/conf', 0700);
mkdir($directory . '/var/db/os-mihomo', 0700, true);
$fixture = $directory . '/conf/config.xml';
$rulePath = '/opnsense/filter/rule[@uuid="5a73c3dc-69b1-4e15-89cb-b542aa2c1154"]';
$assignment = '<opt9><if>tun_mihomo</if><descr>Mihomo TUN</descr><enable>1</enable></opt9>';
$rule = '<rule uuid="5a73c3dc-69b1-4e15-89cb-b542aa2c1154"><type>pass</type><interface>opt9</interface>' .
    '<ipprotocol>inet</ipprotocol><source><network>opt9</network></source><destination><any/></destination>' .
    '<descr>Mihomo TUN Allow</descr></rule>';
$original = '<opnsense><interfaces><lan><if>em1</if></lan>' . $assignment . '</interfaces><filter>' . $rule .
    '<rule uuid="operator-rule"><type>block</type><interface>lan</interface></rule></filter>' .
    '<OPNsense><unboundplus><forwarding><enabled>1</enabled></forwarding>' .
    '<advanced><privateaddress>10.0.0.0/8</privateaddress></advanced><dots/></unboundplus></OPNsense>' .
    '<unknown><keep>operator-value</keep></unknown></opnsense>';
try {
    ownership_seed($directory, $original);
    ownership_run($helper, $directory, 'enable-tun');
    $xpath = ownership_document($fixture);
    ownership_check($xpath->evaluate('string(' . $rulePath . '/ipprotocol)') === 'inet46',
        'The pristine legacy rule did not migrate to both address families.');
    ownership_check($xpath->query($rulePath . '/source/any')->length === 1
        && $xpath->query($rulePath . '/source/network')->length === 0,
        'The pristine legacy rule cannot accept replies with remote source addresses.');
    $migrated = file_get_contents($fixture);
    ownership_run($helper, $directory, 'enable-tun');
    ownership_check(file_get_contents($fixture) === $migrated, 'Repeated migration changed the saved configuration.');
    ownership_run($helper, $directory, 'disable');
    $xpath = ownership_document($fixture);
    ownership_check($xpath->query($rulePath)->length === 0
        && $xpath->query('/opnsense/interfaces/opt9')->length === 0,
        'Pristine migrated integration was not removed.');
    ownership_check($xpath->query('/opnsense/filter/rule[@uuid="operator-rule"]')->length === 1
        && $xpath->evaluate('string(/opnsense/unknown/keep)') === 'operator-value',
        'Cleanup changed unrelated operator configuration.');

    ownership_seed($directory, $original);
    ownership_run($helper, $directory, 'remove');
    $xpath = ownership_document($fixture);
    ownership_check($xpath->query($rulePath)->length === 0
        && $xpath->query('/opnsense/interfaces/opt9')->length === 0,
        'Pristine legacy integration was not removed.');

    $editedRules = [
        'extra condition' => str_replace('</rule>', '<log>1</log></rule>', $rule),
        'changed action' => str_replace('<type>pass</type>', '<type>block</type>', $rule),
        'changed description' => str_replace('Mihomo TUN Allow', 'Operator policy', $rule),
        'restricted source' => str_replace('<network>opt9</network>', '<address>192.0.2.10</address>', $rule),
    ];
    foreach ($editedRules as $case => $editedRule) {
        $editedAssignment = str_replace('</opt9>', '<blockpriv>1</blockpriv></opt9>', $assignment);
        $edited = str_replace([$rule, $assignment], [$editedRule, $editedAssignment], $original);
        ownership_seed($directory, $edited);
        $before = ownership_document($fixture);
        $beforeRule = $before->query($rulePath)->item(0)->C14N();
        $beforeAssignment = $before->query('/opnsense/interfaces/opt9')->item(0)->C14N();
        foreach (['enable-tun', 'disable', 'remove'] as $action) {
            ownership_run($helper, $directory, $action);
            $xpath = ownership_document($fixture);
            ownership_check($xpath->query($rulePath)->length === 1
                && $xpath->query($rulePath)->item(0)->C14N() === $beforeRule,
                'The ' . $case . ' rule was changed or deleted during ' . $action . '.');
            ownership_check($xpath->query('/opnsense/interfaces/opt9')->length === 1
                && $xpath->query('/opnsense/interfaces/opt9')->item(0)->C14N() === $beforeAssignment,
                'An edited rule lost its edited interface assignment during ' . $action . '.');
        }
    }

    $editedAssignment = str_replace('</opt9>', '<blockpriv>1</blockpriv></opt9>', $assignment);
    ownership_seed($directory, str_replace($assignment, $editedAssignment, $original));
    ownership_run($helper, $directory, 'disable');
    $xpath = ownership_document($fixture);
    ownership_check($xpath->query($rulePath)->length === 0
        && $xpath->evaluate('string(/opnsense/interfaces/opt9/blockpriv)') === '1',
        'An edited assignment was deleted while its pristine rule was removed.');

    foreach (['filter' => '<rule uuid="referencing-rule"><interface>lan,opt9</interface></rule>',
              'nat' => '<rule><interface>opt9</interface><target>192.0.2.10</target></rule>'] as $kind => $reference) {
        $referenced = $kind === 'filter'
            ? str_replace('</filter>', $reference . '</filter>', $original)
            : str_replace('</opnsense>', '<nat>' . $reference . '</nat></opnsense>', $original);
        ownership_seed($directory, $referenced);
        ownership_run($helper, $directory, 'remove');
        $xpath = ownership_document($fixture);
        ownership_check($xpath->query($rulePath)->length === 0
            && $xpath->query('/opnsense/interfaces/opt9')->length === 1,
            'An operator ' . $kind . ' reference lost its interface assignment.');
        ownership_check($xpath->query('/opnsense/' . $kind . '/rule[interface[contains(., "opt9")]]')->length === 1,
            'Cleanup changed the operator ' . $kind . ' reference.');
    }
    echo "TUN ownership checks passed: legacy migration, pristine cleanup, edited rules and assignments, and filter/NAT references.\n";
} finally {
    ownership_remove($directory);
}
