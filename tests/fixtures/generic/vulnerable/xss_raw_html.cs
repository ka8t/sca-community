// @audit-fixture
// @rule: xss_raw_html
// @category: security
// @expected: detected
// VULNERABLE: rendu HTML brut via @Html.Raw depuis input HTTP (CWE-79)
public class PageController {
    public string Render() {
        var userInput = Request.QueryString["name"];
        return Html.Raw(userInput);
    }
}
