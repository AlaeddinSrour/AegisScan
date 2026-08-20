using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

internal sealed class SsrfToctouSafe
{
    private readonly HttpClient client = new HttpClient();

    internal Task<HttpResponseMessage> FetchHealthcheck()
    {
        return client.GetAsync("https://status.example.com/health");
    }

    internal string ReadFile(string path)
    {
        try
        {
            return File.ReadAllText(path);
        }
        catch (FileNotFoundException)
        {
            return string.Empty;
        }
    }
}
