using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace Project_X.SwaggerDocFilters
{
    public class ReplaceVersionWithExactValueInPath : IDocumentFilter
    {
        public void Apply(OpenApiDocument swaggerDoc, DocumentFilterContext context)
        {
            if (swaggerDoc == null)
            {
                throw new ArgumentNullException(nameof(swaggerDoc));
            }

            var replacements = new OpenApiPaths();

            foreach (var (key, value) in swaggerDoc.Paths)
            {
                replacements.Add(key.Replace("{version}", (swaggerDoc.Info.Version).Remove(0, 1),
                    StringComparison.InvariantCulture), value);
            }

            swaggerDoc.Paths = replacements;
        }
    }
}
