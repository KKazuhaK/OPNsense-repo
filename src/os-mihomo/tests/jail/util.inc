<?php
/* Minimal synthetic util.inc. The helper requires it because the real
   config.inc reaches for shell_safe() when it stamps a configuration
   revision; the harness substitutes config.inc, so it has to substitute
   this too or the require fails inside the jail. */
function shell_safe($command, $arguments = '')
{
    return trim((string)shell_exec($command . ' ' . $arguments));
}
