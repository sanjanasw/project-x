using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Project_X.Data.Models;

namespace Project_X.Data.Configurations
{
    public class ApplicationUserConfiguration : IEntityTypeConfiguration<ApplicationUser>
    {
        public void Configure(EntityTypeBuilder<ApplicationUser> builder)
        {
            builder.HasIndex(x => x.Email).IsUnique(false);
            builder.HasMany(x => x.RefreshTokens).WithOne().HasForeignKey(x => x.ApplicationUserId)
                .OnDelete(DeleteBehavior.NoAction);
        }
    }
}
