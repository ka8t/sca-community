// @audit-fixture
// @rule: prototype_pollution
// @expected: clean
function safeMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (key === "prototype" || key === "constructor") continue;
        target[key] = source[key];
    }
}
