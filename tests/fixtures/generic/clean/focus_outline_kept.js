// Bonne pratique : style de focus visible personnalisé
document.querySelectorAll('a, button').forEach(el => {
    el.style.outline = '2px solid blue';
});

function setCustomFocusRing(element) {
    element.style.outline = '3px solid #4A90D9';
}
