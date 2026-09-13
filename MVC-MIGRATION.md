# Converting the remaining plugins to the MVC conventions

`os-mihomo` has been converted and is the worked example. The other twelve
packages still serve legacy `.php` pages from `/usr/local/www/`. This describes
what to do, what went wrong doing it the first time, and what to check before
calling a conversion finished.

**Do not convert `os-mihomo`.** It is done, and work on it continues in
parallel.

---

## 1. Why bother

OPNsense 26.7 runs two page systems side by side: 36 legacy `.php` pages under
`/usr/local/www/` and 27 MVC modules addressed as `/ui/<module>`. Legacy is not
deprecated — core still ships `firewall_nat_out.php` and friends — but `/ui/` is
the newer convention and is what someone comparing our plugins with IPsec or
Cron will expect.

Two gains beyond the address:

- The view carries no PHP. It fetches from an API, so page and backend can be
  exercised separately.
- Theme changes stop breaking the layout, **provided you remove hardcoded
  colours while you are in there**. See §6 — this is the highest-value part of
  the work and the easiest to skip.

## 2. What the framework will and will not give you

The model layer (`Model.xml` + `base_form` partials + automatic validation)
mounts onto `config.xml`:

```xml
<model>
    <mount>//OPNsense/cron</mount>
```

If a plugin already keeps its settings in `config.xml`, use that layer: less
code, validation for free.

If a plugin keeps settings in its own state directory — `os-mihomo` does, and
others here do too — **do not move that state into `config.xml` just to reach
the model layer.** Write plain API controllers over the existing store. For
`os-mihomo` that state is deliberately outside `config.xml`; moving it would
undo that decision for a cosmetic gain.

## 3. Files to create

For a plugin named `Example`:

```
src/usr/local/opnsense/mvc/app/controllers/OPNsense/Example/IndexController.php
src/usr/local/opnsense/mvc/app/controllers/OPNsense/Example/Api/ServiceController.php
src/usr/local/opnsense/mvc/app/controllers/OPNsense/Example/Api/SettingsController.php
src/usr/local/opnsense/mvc/app/views/OPNsense/Example/index.volt
```

`IndexController` only picks the view:

```php
namespace OPNsense\Example;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/Example/index');
    }
}
```

API controllers extend `\OPNsense\Base\ApiControllerBase`, return arrays that the
framework encodes as JSON, and reach the backend through
`(new \OPNsense\Core\Backend())->configdRun('example status')`.

Look in `src/usr/local/opnsense/service/conf/actions.d/` first — most plugins
here already define their actions, so the controller is a thin wrapper and needs
no `require_once` of anything under `/usr/local/etc/inc/`.

Menu and ACL move to the MVC form:

```xml
<Example VisibleName="Example" order="10" url="/ui/example">
    <item url="/ui/example/*" visibility="hidden"/>
</Example>
```

```xml
<patterns>
    <pattern>ui/example/*</pattern>
    <pattern>api/example/*</pattern>
</patterns>
```

Then delete the legacy `.php` pages, any log-tailing helper pages, and the
plugin's `/usr/local/etc/inc/*.inc.php` if nothing else uses it. For `os-mihomo`
that was eight PHP files replaced by three controllers and one view.

## 4. The two mistakes that cost the most time

**`OPNsense\Mvc\Request` is not Phalcon's request object.** It has exactly:

```
getClientAddress  getHeader  getJsonRawBody  getMethod
getPost  getQuery  getRawBody  getScheme  getURI
```

`getHttpHost()`, which every Phalcon example uses, raises
`Call to undefined method`. The framework reports that to the browser as
`Unexpected error, check log for details` and writes it to no log you will
find. Use `$this->request->getHeader('Host')`.

**Array responses are HTML-escaped on the way out.** `Mvc/Response.php` runs
`htmlspecialchars($result, ENT_NOQUOTES)` over every array response unless the
controller marks it safe. That is a deliberate XSS defence — leave it on — and
`htmlDecode()` in `opnsense.js` is the helper meant to pair with it:

```js
$('#example-log').text(htmlDecode((data || {}).log || ''));
```

Skip it and a log full of `-->` renders as `--&gt;`. Note that calling the API
with an API key shows clean text, so this only appears in the browser.

When an action fails opaquely, wrap its body in `try/catch` and return
`get_class($e) . ': ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine()`,
call the endpoint with an API key, read the answer, then remove the wrapper.
That is the fastest route to a real message.

## 5. Calling the API while developing

The browser is not the quickest way to test:

```sh
curl -sk -u "$KEY:$SECRET" https://<router>:<port>/api/example/service/status
```

A route answering `Authentication error` rather than 404 is registered
correctly. Clear the caches after changing menu or ACL:

```sh
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json
```

## 6. Themes — currently broken everywhere but `os-mihomo`

Three themes ship, including `opnsense-dark`. A page that hardcodes colours
renders as a white panel inside a dark one. Every remaining plugin does it:

| Package | Hardcoded colours |
| --- | --- |
| `os-ttyd` | 10 |
| `os-speedtest` | 7 |
| `os-lang` | 6 |
| `os-pftop` | 5 |
| `os-lucky` | 3 |
| `os-staticarp` | 3 |
| `os-easytier` | 2 |

Find them with:

```sh
grep -nE '(color|background)\s*:\s*(#|rgb)' src/*/src/usr/local/www/*.php
```

Replace with Bootstrap's semantic classes — `label-success`, `text-muted`,
`alert-warning`, `btn-default` — which every theme defines. The converted
`os-mihomo` view declares no colour at all; match that. A plugin CSS class is
fine as long as it carries only geometry, as `.mihomo-log` does.

Two related traps:

- **A class defined in no theme silently does nothing.** `icon-embed-btn` was
  used in `os-speedtest` and exists nowhere in OPNsense, so those icons sat
  flush against their labels while neighbouring icons using the plugin's own
  class had the gap. Grep for a class before trusting it.
- **An `<input>` with no `type` is skipped by CSS attribute selectors** and
  renders at the wrong width. Two inputs in `os-lucky` had this. Check with
  `grep -nE '<input(?![^>]*type=)'`.

## 7. Markup conventions worth copying

- Section titles go in `<thead>`, fields in `<tbody>`. A title left in the
  striped body sits on a grey band and shifts the stripe of every row after it.
- Labels lead with
  `<a id="help_for_X" class="showhelp"><i class="fa fa-info-circle"></i></a>`
  and the text goes in `<div class="hidden" data-for="help_for_X">`.
- The full-help toggle needs an `id` containing `show_all_help`. In a legacy
  page the shared handler scopes it with `closest('form[id^="frm"]')`, so the
  form needs an id starting with `frm` or the toggle does nothing.
- Dropdowns use `class="selectpicker" data-style="btn-default"`. A plain
  `form-control` select sized with `width:auto` draws its caret over the text.
- Ids must be unique across the whole page. Merging two pages into one is where
  duplicates turn up; `help_for_dashboard` and `show_all_help_page` both
  collided during the `os-mihomo` merge.
- Give a `<pre>` an explicit `max-width` and `overflow:auto`. A long log line
  otherwise widens its table until the panel runs off the page.

## 8. Before calling it done

1. `php -l` every new file.
2. Every endpoint answers with an API key, **including the settings one** — that
   is the one that broke in `os-mihomo`, and the service endpoints passing told
   us nothing about it.
3. Switch to `opnsense-dark` under **System → Settings → General** and look.
4. No secret or credential appears in what the API returns. `os-mihomo` omits
   the dashboard secret and the subscription URL, reporting only whether a URL
   is stored so the form can say it keeps what is there.
5. If the plugin has CLI helpers, copy
   `src/os-mihomo/tests/native/check-undefined.php`. It resolves every function
   each entry point calls against the real tree. It exists because the VNET jail
   harness substitutes `config.inc`, so a missing `require_once('util.inc')`
   passes there and fails on a router — which is exactly what happened.

## 9. Suggested order

Smallest surface first, so the pattern is settled before the fiddly ones:

`os-staticarp` → `os-pftop` → `os-lucky` → `os-easytier` → `os-ddns-go` →
`os-lang` → `os-ttyd` → `os-speedtest` → `os-sing-box`

`os-sing-box` last: four pages, and its shape matches the old `os-mihomo`
closely enough that the converted version is a direct template.

`os-speedtest` already has a background runner and a polling file
(`src/usr/local/opnsense/scripts/speedtest/speedtest.py` writing
`progress.json`); its poll becomes an API action rather than an `?ajax=` query
on the page.
