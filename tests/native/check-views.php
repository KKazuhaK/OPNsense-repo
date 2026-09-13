<?php
/* Compile every selected package view with genuine Phalcon and parse its PHP. */
$loader = '/usr/local/opnsense/mvc/app/config/loader.php';
if (!is_file($loader)) {
    throw new RuntimeException('View compilation requires genuine OPNsense.');
}
require_once($loader);
$packages = array_slice($argv, 1);
if (!$packages) {
    $packages = glob(dirname(__DIR__, 2) . '/src/os-*', GLOB_ONLYDIR);
}
$count = 0;
$failures = [];
foreach ($packages as $package) {
    // Include the legacy src/opnsense layout used by Unboundcustom as well.
    $views = $package . '/src';
    if (!is_dir($views)) { continue; }
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($views,
        FilesystemIterator::SKIP_DOTS));
    foreach ($iterator as $view) {
        if ($view->getExtension() !== 'volt') { continue; }
        $target = tempnam(sys_get_temp_dir(), 'plugin-volt-');
        if ($target === false) { throw new RuntimeException('Unable to stage compiled PHP.'); }
        try {
            $compiler = new \Phalcon\Mvc\View\Engine\Volt\Compiler();
            $compiler->compileFile($view->getPathname(), $target);
            $output = [];
            exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($target) . ' 2>&1', $output, $status);
            if ($status !== 0) {
                throw new RuntimeException(implode(' ', $output));
            }
            $count++;
            printf("PASS %s/%s\n", basename($package), $view->getFilename());
        } catch (Throwable $error) {
            $failures[] = $view->getPathname() . ': ' . $error->getMessage();
        } finally {
            unlink($target);
        }
    }
}
foreach ($failures as $failure) { fwrite(STDERR, $failure . "\n"); }
printf("%d views compiled; %d failures\n", $count, count($failures));
exit($failures ? 1 : 0);
