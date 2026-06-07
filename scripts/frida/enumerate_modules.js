// Observational runtime inspection for a process you own, on a device you own.
//
// Read-only: enumerates loaded modules and a sample of Objective-C classes so
// you can correlate the running App Store build with the static metadata the
// comparison engine extracted. It hooks nothing, patches nothing, and bypasses
// nothing.
//
// Usage (device must be jailbroken or the app re-signed for your own dev cert):
//   frida -U -f org.whispersystems.signal -l scripts/frida/enumerate_modules.js --no-pause
//   # or attach:  frida -U -n Signal -l scripts/frida/enumerate_modules.js

'use strict';

function listModules() {
  const mods = Process.enumerateModules().map(function (m) {
    return { name: m.name, base: m.base.toString(), size: m.size, path: m.path };
  });
  send({ kind: 'modules', count: mods.length, modules: mods });
}

function listObjCClasses(limit) {
  if (!ObjC.available) {
    send({ kind: 'objc', available: false });
    return;
  }
  const names = Object.keys(ObjC.classes);
  // Surface app-specific classes (skip the Apple framework prefixes) up to a cap.
  const appish = names.filter(function (n) {
    return !/^(NS|UI|CA|CF|_|__)/.test(n);
  });
  send({ kind: 'objc', available: true, total: names.length, app_sample: appish.slice(0, limit || 200) });
}

setImmediate(function () {
  try {
    listModules();
    listObjCClasses(200);
    send({ kind: 'done' });
  } catch (e) {
    send({ kind: 'error', message: '' + e });
  }
});
