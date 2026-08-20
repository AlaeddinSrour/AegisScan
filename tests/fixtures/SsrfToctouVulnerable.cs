using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

internal sealed class SsrfToctouVulnerable
{
    private readonly HttpClient client = new HttpClient();

    internal Task<HttpResponseMessage> FetchPreview(HttpRequest request)
    {
        string target = request.Query["url"].ToString();
        return client.GetAsync(target);
    }

    internal string ReadExisting(string path)
    {
        if (File.Exists(path))
        {
            return File.ReadAllText(path);
        }
        return string.Empty;
    }

    internal async Task<string> ReadExistingAsync(string path)
    {
        if (File.Exists(path))
        {
            return await File.ReadAllTextAsync(path);
        }
        return string.Empty;
    }
}
