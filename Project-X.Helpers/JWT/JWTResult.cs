namespace Project_X.Helpers.JWT
{
    public class JWTResult
    {
        public string? Token { get; set; }

        public DateTime Expiration { get; set; }

        public object? User { get; set; }

        public string? RefreshToken { get; set; }
    }
}

