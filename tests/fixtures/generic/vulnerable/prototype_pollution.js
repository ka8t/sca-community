// @audit-fixture
// @rule: prototype_pollution
function merge(target, source) {
    for (const key in source) {
        target[key] = source[key];
    }
}
const payload = JSON.parse(req.body.data);
merge({}, payload);
