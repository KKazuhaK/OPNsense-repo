<?php
/* Every function a CLI script calls must exist once its own includes have run.
   The jail harness swaps config.inc for a stub, so this class of defect can
   only be caught against the real OPNsense tree. */
$lang = ['if','for','foreach','while','switch','return','echo','print','list','array','isset',
         'unset','empty','die','exit','include','require','include_once','require_once','catch',
         'function','fn','match','new','use','elseif','and','or','xor','static','int','string',
         'float','bool','clone','throw','yield','global','endif','endforeach','endwhile','declare'];

function calls_in($src, $lang) {
    /* Drop strings and comments so regex literals cannot look like calls. */
    $src = preg_replace('/\'(?:\\\\.|[^\'\\\\])*\'|"(?:\\\\.|[^"\\\\])*"|\/\*.*?\*\/|\/\/[^\n]*/s', ' ', $src);
    preg_match_all('/(?<![>:$\w])(new\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/', $src, $found, PREG_SET_ORDER);
    $names = [];
    foreach ($found as $hit) {
        if ($hit[1] !== '') { continue; }                 // new ClassName(...)
        if (in_array(strtolower($hit[2]), $lang, true)) { continue; }
        $names[$hit[2]] = true;
    }
    return array_keys($names);
}

$failed = 0;
$root = getenv('MIHOMO_ROOT') ?: '';
foreach ([
    $root . '/usr/local/opnsense/scripts/mihomo/setup_unbound.php' => ['util.inc', 'config.inc'],
] as $file => $includes) {
    if (!is_readable($file)) { printf("  ? %-24s 不存在\n", basename($file)); continue; }
    $pid = pcntl_fork();
    if ($pid === 0) {
        foreach ($includes as $inc) { require_once($inc); }
        $src = file_get_contents($file);
        $missing = [];
        foreach (calls_in($src, $lang) as $name) {
            if (preg_match('/function\s+&?' . preg_quote($name, '/') . '\s*\(/i', $src)) { continue; }
            if (function_exists($name) || class_exists($name)) { continue; }
            $missing[] = $name;
        }
        if ($missing) { printf("  X %-24s 未定义: %s\n", basename($file), implode(', ', $missing)); exit(1); }
        printf("  o %-24s %d 个调用全部可解析\n", basename($file), count(calls_in($src, $lang)));
        exit(0);
    }
    pcntl_waitpid($pid, $status);
    if (pcntl_wexitstatus($status) !== 0) { $failed++; }
}
printf("失败: %d\n", $failed);
exit($failed === 0 ? 0 : 1);
