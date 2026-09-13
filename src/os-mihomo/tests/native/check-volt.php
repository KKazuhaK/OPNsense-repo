#!/usr/local/bin/php
<?php

/*
 * Compile the plugin's Volt views with the framework's own compiler.
 *
 * A template the compiler rejects reaches the browser as "Unexpected error,
 * check log for details" with nothing useful in any log, and no other check
 * here looks at the view as anything but text. Run where OPNsense is
 * installed:  php tests/native/check-volt.php
 */

$loader = '/usr/local/opnsense/mvc/app/config/loader.php';
if (!file_exists($loader)) {
    fwrite(STDERR, "skipped: the framework is verified where it is installed\n");
    exit(0);
}
require_once($loader);

$views = glob(__DIR__ . '/../../src/usr/local/opnsense/mvc/app/views/OPNsense/*/*.volt');
if (!$views) {
    fwrite(STDERR, "error: no views found\n");
    exit(1);
}

$failures = 0;
foreach ($views as $view) {
    $target = tempnam(sys_get_temp_dir(), 'volt-') . '.php';
    try {
        $compiler = new \Phalcon\Mvc\View\Engine\Volt\Compiler();
        $compiler->setOptions(['always' => true, 'compiledPath' => sys_get_temp_dir() . '/',
                               'compiledSeparator' => '_']);
        $compiler->compileFile($view, $target);
        /* A template can compile to PHP that does not parse, so check both. */
        exec(PHP_BINARY . ' -l ' . escapeshellarg($target) . ' 2>&1', $output, $status);
        if ($status !== 0) {
            $failures++;
            printf("FAIL %s: %s\n", basename($view), implode(' ', $output));
        } else {
            printf("ok   %s\n", basename($view));
        }
    } catch (Throwable $error) {
        $failures++;
        printf("FAIL %s: %s: %s\n", basename($view), get_class($error), $error->getMessage());
    } finally {
        @unlink($target);
    }
}
exit($failures === 0 ? 0 : 1);
