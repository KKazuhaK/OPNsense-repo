<?php
/* Every function a WAN Guard entry point calls must exist once its own includes
   have run. Only the real OPNsense tree can prove that; a missing require_once
   would otherwise surface on a router, in the middle of an action. */
$lang = ['if', 'for', 'foreach', 'while', 'switch', 'return', 'echo', 'print', 'list', 'array', 'isset',
         'unset', 'empty', 'die', 'exit', 'include', 'require', 'include_once', 'require_once', 'catch',
         'function', 'fn', 'match', 'new', 'use', 'elseif', 'and', 'or', 'xor', 'static', 'int', 'string',
         'float', 'bool', 'clone', 'throw', 'yield', 'global', 'endif', 'endforeach', 'endwhile', 'declare'];

function calls_in($src, $lang)
{
    /* Drop strings and comments so regex literals cannot look like calls. */
    $src = preg_replace('/\'(?:\\\\.|[^\'\\\\])*\'|"(?:\\\\.|[^"\\\\])*"|\/\*.*?\*\/|\/\/[^\n]*/s', ' ', $src);
    /* Match complete qualified names so constructor tails cannot become calls. */
    preg_match_all('/(?<![>:$\w\\\\])(new\s+)?(\\\\?[a-zA-Z_][a-zA-Z0-9_]*(?:\\\\[a-zA-Z_][a-zA-Z0-9_]*)*)\s*\(/', $src, $found, PREG_SET_ORDER);
    $names = [];
    foreach ($found as $hit) {
        if ($hit[1] !== '') {
            continue;
        }
        if (in_array(strtolower($hit[2]), $lang, true)) {
            continue;
        }
        $names[$hit[2]] = true;
    }
    return array_keys($names);
}

function static_calls_in($src)
{
    /* Class::method( references, which the call pattern above skips. */
    $src = preg_replace('/\'(?:\\\\.|[^\'\\\\])*\'|"(?:\\\\.|[^"\\\\])*"|\/\*.*?\*\/|\/\/[^\n]*/s', ' ', $src);
    preg_match_all('/(?<![>:$\w\\\\])(\\\\?[a-zA-Z_][a-zA-Z0-9_]*(?:\\\\[a-zA-Z_][a-zA-Z0-9_]*)*)::([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/', $src, $found, PREG_SET_ORDER);
    $names = [];
    foreach ($found as $hit) {
        if (!in_array(strtolower($hit[1]), ['self', 'static', 'parent'], true)) {
            $names[$hit[1] . '::' . $hit[2]] = [$hit[1], $hit[2]];
        }
    }
    return array_values($names);
}

if (!is_file('/usr/local/etc/inc/config.inc') || !function_exists('pcntl_fork')) {
    fwrite(STDERR, "Requires the native OPNsense includes and pcntl.\n");
    exit(77);
}
$root = $argv[1] ?? dirname(__DIR__, 2) . '/src';
$failed = 0;
foreach ([
    $root . '/usr/local/opnsense/scripts/wanguard/helper.php' => ['config.inc', 'util.inc', 'interfaces.inc'],
    /* plugins.inc has already loaded these when it includes a plugin. */
    $root . '/usr/local/etc/inc/plugins.inc.d/wanguard.inc' => ['config.inc', 'util.inc'],
] as $file => $includes) {
    if (!is_readable($file)) {
        printf("  ? %-24s missing\n", basename($file));
        $failed++;
        continue;
    }
    $pid = pcntl_fork();
    if ($pid === 0) {
        foreach ($includes as $include) {
            require_once($include);
        }
        $src = file_get_contents($file);
        $missing = [];
        foreach (calls_in($src, $lang) as $name) {
            if (preg_match('/function\s+&?' . preg_quote($name, '/') . '\s*\(/i', $src)) {
                continue;
            }
            if (function_exists($name) || class_exists($name)) {
                continue;
            }
            $missing[] = $name;
        }
        $statics = static_calls_in($src);
        foreach ($statics as [$class, $method]) {
            if (!class_exists($class) || !is_callable([$class, $method])) {
                $missing[] = $class . '::' . $method;
            }
        }
        if ($missing) {
            printf("  X %-24s undefined: %s\n", basename($file), implode(', ', $missing));
            exit(1);
        }
        printf("  o %-24s all %d calls and %d static calls resolve\n", basename($file),
            count(calls_in($src, $lang)), count($statics));
        exit(0);
    }
    pcntl_waitpid($pid, $status);
    if (pcntl_wexitstatus($status) !== 0) {
        $failed++;
    }
}
printf("failed: %d\n", $failed);
exit($failed === 0 ? 0 : 1);
