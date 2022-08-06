namespace Project_X.Helpers
{
    public class AppSettings
    {
        public EmailConfiguration? EmailConfiguration { get; set; }
    }

    public class EmailConfiguration
    {
        public string? EmailFrom { get; set; }
        public string? SmtpHost { get; set; }
        public int SmtpPort { get; set; }
        public string? SmtpUser { get; set; }
        public string? SmtpPass { get; set; }
    }
}
