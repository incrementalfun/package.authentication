using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Incremental.Common.Authentication.Jwt.Testing.Context;

public class TestingDbContext : IdentityDbContext<IdentityUser>
{
    public TestingDbContext(DbContextOptions<TestingDbContext> options)
        : base(options)
    {
    }
}