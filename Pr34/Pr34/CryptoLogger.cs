using System.Text.Json;

namespace Pr34
{
    public static class CryptoLogger
    {
        public static void Log(string type, string message)
        {
            var entry = new
            {
                time = DateTime.Now,
                type,
                message
            };

            File.AppendAllText(
                "log.json",
                JsonSerializer.Serialize(entry) + Environment.NewLine);
        }
    }
}
