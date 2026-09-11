// Fixture vulnérable : path traversal C# — fichier ouvert avec entrée utilisateur
using Microsoft.AspNetCore.Mvc;
using System.IO;

public class FileController : Controller
{
    public IActionResult Download()
    {
        var path = Request["path"];
        var content = File.ReadAllText(path);
        return Content(content);
    }
}
