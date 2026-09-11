// @audit-fixture
// @rule: focus_outline_removed
// @category: ux
// @expected: clean
// Custom focus ring
document.querySelectorAll('a, button').forEach(el => {
    el.style.outline = '2px solid blue';
});
