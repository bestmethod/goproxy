function countrySelect(country) {
    var selector = document.getElementById("country-" + country);
    if (selector != null) {
        selector.selected = true;
    }
}
