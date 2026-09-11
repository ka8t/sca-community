// Mauvaise pratique : suppression de l'indicateur de focus
document.querySelectorAll('a, button').forEach(el => {
    el.style.outline = 'none';
});

function disableFocusRing(element) {
    element.style.outline = '0';
}
