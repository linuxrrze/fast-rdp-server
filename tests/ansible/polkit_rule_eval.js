// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
// Evaluates a polkit .rules file the way polkitd does (src/polkitbackend/init.js):
// polkit.addRule() callbacks run in order, the first truthy result wins.
//   node polkit_rule_eval.js RULES_FILE < cases.json
// cases.json: [{"action": "org.freedesktop.login1.power-off", "user": "alice",
//               "groups": ["alice"], "local": false, "active": true}, ...]
// Prints a JSON list with one result per case ("no", "auth_admin_keep", ...; null when
// no rule answered). Only the polkit object is visible to the rule, as in polkitd.
"use strict";
const fs = require("fs");
const vm = require("vm");

const polkit = {
    _ruleFuncs: [],
    addRule(f) { this._ruleFuncs.push(f); },
    addAdminRule() {},
    log() {},
    spawn() { throw new Error("polkit.spawn not available in tests"); },
    Result: {
        NO: "no", YES: "yes", AUTH_SELF: "auth_self", AUTH_SELF_KEEP: "auth_self_keep",
        AUTH_ADMIN: "auth_admin", AUTH_ADMIN_KEEP: "auth_admin_keep", NOT_HANDLED: null,
    },
};
vm.runInNewContext(fs.readFileSync(process.argv[2], "utf8"), { polkit }, { filename: process.argv[2] });

const cases = JSON.parse(fs.readFileSync(0, "utf8"));
const results = cases.map((c) => {
    const action = { id: c.action, lookup: (k) => (c.details || {})[k] };
    const subject = {
        user: c.user, groups: c.groups || [], local: !!c.local, active: !!c.active,
        seat: c.seat || "", session: c.session || "", pid: 1234,
        isInGroup(g) { return this.groups.indexOf(g) >= 0; },
    };
    for (const f of polkit._ruleFuncs) {
        const r = f(action, subject);
        if (r) return r;
    }
    return null;
});
process.stdout.write(JSON.stringify(results));
