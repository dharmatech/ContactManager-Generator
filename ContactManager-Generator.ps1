
# Set-PSDebug -Trace 0
# Set-PSDebug -Trace 1

$ErrorActionPreference = 'Stop'
# ----------------------------------------------------------------------
function Edit ($File, $Replacing, $With)
{
    (Get-Content $File -Raw).Replace($Replacing, $With) | Set-Content $File
}
# ----------------------------------------------------------------------
# cd C:\Users\dharm\Dropbox\Documents\VisualStudio\ContactManager

# cd C:\Temp

if (Test-Path ContactManager)
{
    $date = Get-Date -Format 'yyyy-MM-dd-HH-mm'

    Move-Item ContactManager _ContactManager-$date
}
# ----------------------------------------------------------------------
New-Item -ItemType Directory -Name ContactManager

cd .\ContactManager

dotnet new webapp --auth Individual --use-local-db

dotnet new gitignore

git init

$ErrorActionPreference = 'Continue'
git add . 
$ErrorActionPreference = 'Stop'

git commit --message 'Initial checkin'

# code .

New-Item -ItemType Directory -Name Models

# ----------------------------------------------------------------------
@"
using System.ComponentModel.DataAnnotations;

namespace ContactManager.Models
{
    public class Contact
    {
        public int ContactId { get; set; }
        public string Name { get; set; }
        public string Address { get; set; }
        public string City { get; set; }
        public string State { get; set; }
        public string Zip { get; set; }
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }
    }
}

"@ | Set-Content .\Models\Contact.cs

git add .
git commit --message 'Add Contact.cs'
# ----------------------------------------------------------------------

dotnet add package Microsoft.VisualStudio.Web.CodeGeneration.Design

$ErrorActionPreference = 'Continue'
dotnet tool install --global dotnet-aspnet-codegenerator
$ErrorActionPreference = 'Stop'

dotnet aspnet-codegenerator razorpage `
    -m Contact `
    --useDefaultLayout `
    --dataContext ApplicationDbContext `
    --relativeFolderPath Pages\Contacts `
    --referenceScriptLibraries

dotnet ef database drop -f

dotnet ef migrations add initial

dotnet ef database update

git add .
git commit --message 'Add Contact via scaffolding'
# ----------------------------------------------------------------------
$file = '.\Pages\Shared\_Layout.cshtml'

$original_text = @"
<a class="navbar-brand" asp-area="" asp-page="/Index">ContactManager</a>
"@

$replacement_text = @"
<a class="navbar-brand" asp-area="" asp-page="/Contacts/Index">ContactManager</a>
"@

Edit $file -Replacing $original_text -With $replacement_text


git add .
git commit --message 'Update ContactManager anchor'
# ----------------------------------------------------------------------
@"
using ContactManager.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Threading.Tasks;

// dotnet aspnet-codegenerator razorpage -m Contact -dc ApplicationDbContext -udl -outDir Pages\Contacts --referenceScriptLibraries

namespace ContactManager.Data
{
    public static class SeedData
    {
        public static async Task Initialize(IServiceProvider serviceProvider, string testUserPw)
        {
            using (var context = new ApplicationDbContext(
                serviceProvider.GetRequiredService<DbContextOptions<ApplicationDbContext>>()))
            {              
                SeedDB(context, "0");
            }
        }        

        public static void SeedDB(ApplicationDbContext context, string adminID)
        {
            if (context.Contact.Any())
            {
                return;   // DB has been seeded
            }

            context.Contact.AddRange(
                new Contact
                {
                    Name = "Debra Garcia",
                    Address = "1234 Main St",
                    City = "Redmond",
                    State = "WA",
                    Zip = "10999",
                    Email = "debra@example.com"
                },
                new Contact
                {
                    Name = "Thorsten Weinrich",
                    Address = "5678 1st Ave W",
                    City = "Redmond",
                    State = "WA",
                    Zip = "10999",
                    Email = "thorsten@example.com"
                },
             new Contact
             {
                 Name = "Yuhong Li",
                 Address = "9012 State st",
                 City = "Redmond",
                 State = "WA",
                 Zip = "10999",
                 Email = "yuhong@example.com"
             },
             new Contact
             {
                 Name = "Jon Orton",
                 Address = "3456 Maple St",
                 City = "Redmond",
                 State = "WA",
                 Zip = "10999",
                 Email = "jon@example.com"
             },
             new Contact
             {
                 Name = "Diliana Alexieva-Bosseva",
                 Address = "7890 2nd Ave E",
                 City = "Redmond",
                 State = "WA",
                 Zip = "10999",
                 Email = "diliana@example.com"
             }
             );
            context.SaveChanges();
        }

    }
}
"@ | Set-Content .\Data\SeedData.cs
# ----------------------------------------------------------------------
@"
using ContactManager.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;

namespace ContactManager
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var host = CreateHostBuilder(args).Build();

            using (var scope = host.Services.CreateScope())
            {
                var services = scope.ServiceProvider;

                try
                {
                    var context = services.GetRequiredService<ApplicationDbContext>();
                    context.Database.Migrate();
                    SeedData.Initialize(services, "not used");
                }
                catch (Exception ex)
                {
                    var logger = services.GetRequiredService<ILogger<Program>>();
                    logger.LogError(ex, "An error occurred seeding the DB.");
                }
            }

            host.Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}
"@ | Set-Content .\Program.cs

git add .
git commit --message 'SeedData'
# ----------------------------------------------------------------------
$file = '.\Models\Contact.cs'

$original_text = @"
    public class Contact
"@

$replacement_text = @"
    public enum ContactStatus
    {
        Submitted,
        Approved,
        Rejected
    }

    public class Contact
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
$file = '.\Models\Contact.cs'

$original_text = @"
        public int ContactId { get; set; }
"@

$replacement_text = @"
        public int ContactId { get; set; }
        public string OwnerID { get; set; }
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
$file = '.\Models\Contact.cs'

$original_text = @"
        public string Email { get; set; }
"@

$replacement_text = @"
        public string Email { get; set; }
        public ContactStatus Status { get; set; }
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
dotnet ef migrations add userID_Status
dotnet ef database update


git add .
git commit --message 'Contact : OwnerID and Status'
# ----------------------------------------------------------------------
$file = '.\Startup.cs'

$original_text = @"
            services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
                .AddEntityFrameworkStores<ApplicationDbContext>();
"@

$replacement_text = @"
            services
                .AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
                .AddRoles<IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>();
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
git add .
git commit --message 'Startup : AddRoles'
# ----------------------------------------------------------------------
# Require authenticated users

$file = '.\Startup.cs'

$original_text = @"
using Microsoft.Extensions.Hosting;
"@

$replacement_text = @"
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authorization;
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
$file = '.\Startup.cs'

$original_text = @"
            services.AddRazorPages();
"@

$replacement_text = @"
            services.AddRazorPages();

            services.AddAuthorization(options => 
            {
                options.FallbackPolicy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
            });
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
$file = '.\Pages\Index.cshtml.cs'

$original_text = @"
using System.Threading.Tasks;
"@

$replacement_text = @"
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
$file = '.\Pages\Index.cshtml.cs'

$original_text = @"
    public class IndexModel : PageModel
"@

$replacement_text = @"
    [AllowAnonymous]
    public class IndexModel : PageModel
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
# .\Pages\Index.cshtml.cs
# ----------------------------------------------------------------------
$file = '.\Pages\Privacy.cshtml.cs'

$original_text = @"
using System.Threading.Tasks;
"@

$replacement_text = @"
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
$file = '.\Pages\Privacy.cshtml.cs'

$original_text = @"
    public class PrivacyModel : PageModel
"@

$replacement_text = @"
    [AllowAnonymous]
    public class PrivacyModel : PageModel
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
git add .
git commit --message 'Require authenticated users'
# ----------------------------------------------------------------------
# Configure the test account
# ----------------------------------------------------------------------
dotnet user-secrets set SeedUserPW Secret123!
# ----------------------------------------------------------------------
$file = '.\Program.cs'

$original_text = @"
using Microsoft.EntityFrameworkCore;
"@

$replacement_text = @"
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
$file = '.\Program.cs'

$original_text = @"
                    var context = services.GetRequiredService<ApplicationDbContext>();
                    context.Database.Migrate();
                    SeedData.Initialize(services, "not used");
"@

$replacement_text = @"
                    var context = services.GetRequiredService<ApplicationDbContext>();
                    context.Database.Migrate();

                    var config = host.Services.GetRequiredService<IConfiguration>();

                    var testUserPw = config["SeedUserPW"];

                    SeedData.Initialize(services, testUserPw).Wait();
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
git add .
git commit --message 'Configure the test account'
# ----------------------------------------------------------------------
# Review the contact operations requirements class
# https://docs.microsoft.com/en-us/aspnet/core/security/authorization/secure-data?view=aspnetcore-5.0#review-the-contact-operations-requirements-class
# ----------------------------------------------------------------------
New-Item -ItemType Directory -Name Authorization

@"
using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace ContactManager.Authorization
{
    public static class ContactOperations
    {
        public static OperationAuthorizationRequirement Create  = new OperationAuthorizationRequirement {Name=Constants.CreateOperationName};
        public static OperationAuthorizationRequirement Read    = new OperationAuthorizationRequirement {Name=Constants.ReadOperationName};  
        public static OperationAuthorizationRequirement Update  = new OperationAuthorizationRequirement {Name=Constants.UpdateOperationName}; 
        public static OperationAuthorizationRequirement Delete  = new OperationAuthorizationRequirement {Name=Constants.DeleteOperationName};
        public static OperationAuthorizationRequirement Approve = new OperationAuthorizationRequirement {Name=Constants.ApproveOperationName};
        public static OperationAuthorizationRequirement Reject  = new OperationAuthorizationRequirement {Name=Constants.RejectOperationName};
    }

    public class Constants
    {
        public static readonly string CreateOperationName  = "Create";
        public static readonly string ReadOperationName    = "Read";
        public static readonly string UpdateOperationName  = "Update";
        public static readonly string DeleteOperationName  = "Delete";
        public static readonly string ApproveOperationName = "Approve";
        public static readonly string RejectOperationName  = "Reject";

        public static readonly string ContactAdministratorsRole = "ContactAdministrators";
        public static readonly string ContactManagersRole       = "ContactManagers";
    }
}
"@ | Set-Content .\Authorization\ContactOperations.cs
# ----------------------------------------------------------------------
git add .
git commit --message 'Authorization/ContactOperations.cs'
# ----------------------------------------------------------------------
# Create the test accounts and update the contacts
# (this section depends on `ContactOperations` and `Constants`)
# https://docs.microsoft.com/en-us/aspnet/core/security/authorization/secure-data?view=aspnetcore-5.0#review-the-contact-operations-requirements-class
# ----------------------------------------------------------------------
$file = '.\Data\SeedData.cs'

$original_text = @"
using ContactManager.Models;
"@

$replacement_text = @"
using ContactManager.Models;
using ContactManager.Authorization;
using Microsoft.AspNetCore.Identity;
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
$file = '.\Data\SeedData.cs'

$original_text = @"
        public static async Task Initialize(IServiceProvider serviceProvider, string testUserPw)
        {
            using (var context = new ApplicationDbContext(
                serviceProvider.GetRequiredService<DbContextOptions<ApplicationDbContext>>()))
            {              
                SeedDB(context, "0");
            }
        }        
"@

$replacement_text = @"
        private static async Task<string> EnsureUser(IServiceProvider serviceProvider, string testUserPw, string UserName)
        {
            var userManager = serviceProvider.GetService<UserManager<IdentityUser>>();

            var user = await userManager.FindByNameAsync(UserName);

            if (user == null)
            {
                user = new IdentityUser()
                {
                    UserName = UserName,
                    EmailConfirmed = true
                };

                await userManager.CreateAsync(user, testUserPw);
            }

            if (user == null)
                throw new Exception("The password is probably not strong enough");

            return user.Id;
        }

        private static async Task<IdentityResult> EnsureRole(IServiceProvider serviceProvider, string uid, string role)
        {
            IdentityResult IR = null;

            var roleManager = serviceProvider.GetService<RoleManager<IdentityRole>>();

            if (roleManager == null)
                throw new Exception("roleManager null");

            if (!await roleManager.RoleExistsAsync(role))
                IR = await roleManager.CreateAsync(new IdentityRole(role));

            var userManager = serviceProvider.GetService<UserManager<IdentityUser>>();

            var user = await userManager.FindByIdAsync(uid);

            if (user == null)
                throw new Exception("The testUserPw password was probably not strong enough");

            IR = await userManager.AddToRoleAsync(user, role);

            return IR;
        }

        public static async Task Initialize(IServiceProvider serviceProvider, string testUserPw)
        {
            using (var context = new ApplicationDbContext(
                serviceProvider.GetRequiredService<DbContextOptions<ApplicationDbContext>>()))
            {
                var adminID = await EnsureUser(serviceProvider, testUserPw, "admin@contoso.com");

                await EnsureRole(serviceProvider, adminID, Constants.ContactAdministratorsRole);

                var managerID = await EnsureUser(serviceProvider, testUserPw, "manager@contoso.com");

                await EnsureRole(serviceProvider, managerID, Constants.ContactManagersRole);

                SeedDB(context, adminID);
            }
        }        
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
git add .
git commit --message 'SeedData : EnsureUser and EnsureRole'
# ----------------------------------------------------------------------
$file = '.\Data\SeedData.cs'

$original_text = @"
        public static void SeedDB(ApplicationDbContext context, string adminID)
        {
            if (context.Contact.Any())
            {
                return;   // DB has been seeded
            }

            context.Contact.AddRange(
                new Contact
                {
                    Name = "Debra Garcia",
                    Address = "1234 Main St",
                    City = "Redmond",
                    State = "WA",
                    Zip = "10999",
                    Email = "debra@example.com"
                },
                new Contact
                {
                    Name = "Thorsten Weinrich",
                    Address = "5678 1st Ave W",
                    City = "Redmond",
                    State = "WA",
                    Zip = "10999",
                    Email = "thorsten@example.com"
                },
             new Contact
             {
                 Name = "Yuhong Li",
                 Address = "9012 State st",
                 City = "Redmond",
                 State = "WA",
                 Zip = "10999",
                 Email = "yuhong@example.com"
             },
             new Contact
             {
                 Name = "Jon Orton",
                 Address = "3456 Maple St",
                 City = "Redmond",
                 State = "WA",
                 Zip = "10999",
                 Email = "jon@example.com"
             },
             new Contact
             {
                 Name = "Diliana Alexieva-Bosseva",
                 Address = "7890 2nd Ave E",
                 City = "Redmond",
                 State = "WA",
                 Zip = "10999",
                 Email = "diliana@example.com"
             }
             );
            context.SaveChanges();
        }
"@

$replacement_text = @"
        public static void SeedDB(ApplicationDbContext context, string adminID)
        {
            if (context.Contact.Any())
            {
                return;   // DB has been seeded
            }

            context.Contact.AddRange(
                new Contact
                {
                    Name = "Debra Garcia",
                    Address = "1234 Main St",
                    City = "Redmond",
                    State = "WA",
                    Zip = "10999",
                    Email = "debra@example.com",
                    Status = ContactStatus.Approved,
                    OwnerID = adminID
                },
                new Contact
                {
                    Name = "Thorsten Weinrich",
                    Address = "5678 1st Ave W",
                    City = "Redmond",
                    State = "WA",
                    Zip = "10999",
                    Email = "thorsten@example.com",
                    Status = ContactStatus.Approved,
                    OwnerID = adminID
                },
                new Contact
                {
                    Name = "Yuhong Li",
                    Address = "9012 State st",
                    City = "Redmond",
                    State = "WA",
                    Zip = "10999",
                    Email = "yuhong@example.com",
                    Status = ContactStatus.Approved,
                    OwnerID = adminID
                },
                new Contact
                {
                    Name = "Jon Orton",
                    Address = "3456 Maple St",
                    City = "Redmond",
                    State = "WA",
                    Zip = "10999",
                    Email = "jon@example.com",
                    Status = ContactStatus.Submitted,
                    OwnerID = adminID
                },
                new Contact
                {
                    Name = "Diliana Alexieva-Bosseva",
                    Address = "7890 2nd Ave E",
                    City = "Redmond",
                    State = "WA",
                    Zip = "10999",
                    Email = "diliana@example.com",
                    Status = ContactStatus.Rejected,
                    OwnerID = adminID
                }
             );
            context.SaveChanges();
        }
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
git add .
git commit --message 'Update SeedDB'
# ----------------------------------------------------------------------
# Create owner, manager, and administrator authorization handlers
# https://docs.microsoft.com/en-us/aspnet/core/security/authorization/secure-data?view=aspnetcore-5.0#create-owner-manager-and-administrator-authorization-handlers
# ----------------------------------------------------------------------
@"
using ContactManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace ContactManager.Authorization
{
    public class ContactIsOwnerAuthorizationHandler
                : AuthorizationHandler<OperationAuthorizationRequirement, Contact>
    {
        UserManager<IdentityUser> _userManager;

        public ContactIsOwnerAuthorizationHandler(UserManager<IdentityUser> 
            userManager)
        {
            _userManager = userManager;
        }

        protected override Task
            HandleRequirementAsync(AuthorizationHandlerContext context,
                                   OperationAuthorizationRequirement requirement,
                                   Contact resource)
        {
            if (context.User == null || resource == null)
            {
                return Task.CompletedTask;
            }

            // If not asking for CRUD permission, return.

            if (requirement.Name != Constants.CreateOperationName &&
                requirement.Name != Constants.ReadOperationName   &&
                requirement.Name != Constants.UpdateOperationName &&
                requirement.Name != Constants.DeleteOperationName )
            {
                return Task.CompletedTask;
            }

            if (resource.OwnerID == _userManager.GetUserId(context.User))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
"@ | Set-Content .\Authorization\ContactIsOwnerAuthorizationHandler.cs
# ----------------------------------------------------------------------
git add .
git commit --message 'ContactIsOwnerAuthorizationHandler'
# ----------------------------------------------------------------------
# Create a manager authorization handler
# https://docs.microsoft.com/en-us/aspnet/core/security/authorization/secure-data?view=aspnetcore-5.0#create-a-manager-authorization-handler
# ----------------------------------------------------------------------
@"
using System.Threading.Tasks;
using ContactManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Identity;

namespace ContactManager.Authorization
{
    public class ContactManagerAuthorizationHandler :
        AuthorizationHandler<OperationAuthorizationRequirement, Contact>
    {
        protected override Task
            HandleRequirementAsync(AuthorizationHandlerContext context,
                                   OperationAuthorizationRequirement requirement,
                                   Contact resource)
        {
            if (context.User == null || resource == null)
            {
                return Task.CompletedTask;
            }

            // If not asking for approval/reject, return.
            if (requirement.Name != Constants.ApproveOperationName &&
                requirement.Name != Constants.RejectOperationName)
            {
                return Task.CompletedTask;
            }

            // Managers can approve or reject.
            if (context.User.IsInRole(Constants.ContactManagersRole))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
"@ | Set-Content .\Authorization\ContactManagerAuthorizationHandler.cs
# ----------------------------------------------------------------------
git add .
git commit --message 'ContactManagerAuthorizationHandler'
# ----------------------------------------------------------------------
# Create an administrator authorization handler
# https://docs.microsoft.com/en-us/aspnet/core/security/authorization/secure-data?view=aspnetcore-5.0#create-an-administrator-authorization-handler
# ----------------------------------------------------------------------
@"
using System.Threading.Tasks;
using ContactManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace ContactManager.Authorization
{
    public class ContactAdministratorsAuthorizationHandler
                    : AuthorizationHandler<OperationAuthorizationRequirement, Contact>
    {
        protected override Task HandleRequirementAsync(
                                              AuthorizationHandlerContext context,
                                    OperationAuthorizationRequirement requirement, 
                                     Contact resource)
        {
            if (context.User == null)
            {
                return Task.CompletedTask;
            }

            // Administrators can do anything.
            if (context.User.IsInRole(Constants.ContactAdministratorsRole))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
"@ | Set-Content .\Authorization\ContactAdministratorsAuthorizationHandler.cs
# ----------------------------------------------------------------------
git add .
git commit --message 'ContactAdministratorsAuthorizationHandler'
# ----------------------------------------------------------------------
# Register the authorization handlers
# https://docs.microsoft.com/en-us/aspnet/core/security/authorization/secure-data?view=aspnetcore-5.0#register-the-authorization-handlers
# ----------------------------------------------------------------------
$file = '.\Startup.cs'

$original_text = @"
using Microsoft.AspNetCore.Authorization;
"@

$replacement_text = @"
using Microsoft.AspNetCore.Authorization;
using ContactManager.Authorization;
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
$file = '.\Startup.cs'

$original_text = @"
            services.AddAuthorization(options => 
            {
                options.FallbackPolicy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
            });
"@

$replacement_text = @"
            services.AddAuthorization(options => 
            {
                options.FallbackPolicy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
            });

            services.AddScoped<IAuthorizationHandler, ContactIsOwnerAuthorizationHandler>();

            services.AddSingleton<IAuthorizationHandler, ContactAdministratorsAuthorizationHandler>();
            services.AddSingleton<IAuthorizationHandler, ContactManagerAuthorizationHandler>();
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
git add .
git commit --message 'Register the authorization handlers'
# ----------------------------------------------------------------------
# Create a base class for the Contacts Razor Pages
# https://docs.microsoft.com/en-us/aspnet/core/security/authorization/secure-data?view=aspnetcore-5.0#create-a-base-class-for-the-contacts-razor-pages
# ----------------------------------------------------------------------
@"
using ContactManager.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ContactManager.Pages.Contacts
{
    public class DI_BasePageModel : PageModel
    {
        protected ApplicationDbContext Context { get; }
        protected IAuthorizationService AuthorizationService { get; }
        protected UserManager<IdentityUser> UserManager { get; }

        public DI_BasePageModel(
            ApplicationDbContext context,
            IAuthorizationService authorizationService,
            UserManager<IdentityUser> userManager) : base()
        {
            Context = context;
            UserManager = userManager;
            AuthorizationService = authorizationService;
        } 
    }
}
"@ | Set-Content .\Pages\Contacts\DI_BasePageModel.cs
# ----------------------------------------------------------------------
git add .
git commit --message 'DI_BasePageModel'
# ----------------------------------------------------------------------
# Update the CreateModel
# https://docs.microsoft.com/en-us/aspnet/core/security/authorization/secure-data?view=aspnetcore-5.0#update-the-createmodel
# ----------------------------------------------------------------------
$file = '.\Pages\Contacts\Create.cshtml.cs'

$original_text = @"
using ContactManager.Models;
"@

$replacement_text = @"
using ContactManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using ContactManager.Authorization;
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
$file = '.\Pages\Contacts\Create.cshtml.cs'

$original_text = @"
    public class CreateModel : PageModel
    {
        private readonly ContactManager.Data.ApplicationDbContext _context;

        public CreateModel(ContactManager.Data.ApplicationDbContext context)
        {
            _context = context;
        }
"@

$replacement_text = @"
    public class CreateModel : DI_BasePageModel
    {
        public CreateModel(
            ApplicationDbContext context, 
            IAuthorizationService authorizationService, 
            UserManager<IdentityUser> userManager)
            : base(context, authorizationService, userManager)
        {
        }
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
$file = '.\Pages\Contacts\Create.cshtml.cs'

$original_text = @"
using Microsoft.AspNetCore.Identity;
"@

$replacement_text = @"
using Microsoft.AspNetCore.Identity;
using ContactManager.Authorization;
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
$file = '.\Pages\Contacts\Create.cshtml.cs'

$original_text = @"
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            _context.Contact.Add(Contact);
            await _context.SaveChangesAsync();

            return RedirectToPage("./Index");
        }
"@

$replacement_text = @"
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            Contact.OwnerID = UserManager.GetUserId(User);

            // requires using ContactManager.Authorization;
            var isAuthorized = await AuthorizationService.AuthorizeAsync(User, Contact, ContactOperations.Create);
            if (!isAuthorized.Succeeded)
            {
                return Forbid();
            }

            Context.Contact.Add(Contact);
            await Context.SaveChangesAsync();

            return RedirectToPage("./Index");
        }
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
git add .
git commit --message 'Update Pages\Contacts\Create.cshtml.cs'
# ----------------------------------------------------------------------
# Update the IndexModel
# https://docs.microsoft.com/en-us/aspnet/core/security/authorization/secure-data?view=aspnetcore-5.0#update-the-indexmodel
# ----------------------------------------------------------------------
@"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using ContactManager.Data;
using ContactManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using ContactManager.Authorization;

namespace ContactManager.Pages.Contacts
{
    public class IndexModel : DI_BasePageModel
    {
        public IndexModel(
            ApplicationDbContext context,
            IAuthorizationService authorizationService,
            UserManager<IdentityUser> userManager)
            : base(context, authorizationService, userManager)
        {
        }

        public IList<Contact> Contact { get; set; }

        public async Task OnGetAsync()
        {
            var contacts = from c in Context.Contact
                           select c;

            var isAuthorized = User.IsInRole(Constants.ContactManagersRole) ||
                               User.IsInRole(Constants.ContactAdministratorsRole);

            var currentUserId = UserManager.GetUserId(User);

            // Only approved contacts are shown UNLESS you're authorized to see them
            // or you are the owner.
            if (!isAuthorized)
            {
                contacts = contacts.Where(c => 
                    c.Status == ContactStatus.Approved || 
                    c.OwnerID == currentUserId);
            }

            Contact = await contacts.ToListAsync();
        }
    }
}

"@ | Set-Content .\Pages\Contacts\Index.cshtml.cs
# ----------------------------------------------------------------------
git add .
git commit --message 'Update Pages\Contacts\Index.cshtml.cs'
# ----------------------------------------------------------------------
# Update the EditModel
# https://docs.microsoft.com/en-us/aspnet/core/security/authorization/secure-data?view=aspnetcore-5.0#update-the-editmodel
# ----------------------------------------------------------------------
@"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using ContactManager.Data;
using ContactManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using ContactManager.Authorization;

namespace ContactManager.Pages.Contacts
{
    public class EditModel : DI_BasePageModel
    {
        public EditModel(
            ApplicationDbContext context,
            IAuthorizationService authorizationService,
            UserManager<IdentityUser> userManager)
            : base(context, authorizationService, userManager)
        {
        }

        [BindProperty]
        public Contact Contact { get; set; }

        public async Task<IActionResult> OnGetAsync(int id)
        {
            Contact = await Context.Contact.FirstOrDefaultAsync(
                                                 m => m.ContactId == id);

            if (Contact == null)
            {
                return NotFound();
            }

            var isAuthorized = await AuthorizationService.AuthorizeAsync(
                                                      User, Contact,
                                                      ContactOperations.Update);
            if (!isAuthorized.Succeeded)
            {
                return Forbid();
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(int id)
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Fetch Contact from DB to get OwnerID.
            var contact = await Context
                .Contact.AsNoTracking()
                .FirstOrDefaultAsync(m => m.ContactId == id);

            if (contact == null)
            {
                return NotFound();
            }

            var isAuthorized = await AuthorizationService.AuthorizeAsync(
                                                     User, contact,
                                                     ContactOperations.Update);
            if (!isAuthorized.Succeeded)
            {
                return Forbid();
            }

            Contact.OwnerID = contact.OwnerID;

            Context.Attach(Contact).State = EntityState.Modified;

            if (Contact.Status == ContactStatus.Approved)
            {
                // If the contact is updated after approval, 
                // and the user cannot approve,
                // set the status back to submitted so the update can be
                // checked and approved.
                var canApprove = await AuthorizationService.AuthorizeAsync(User,
                                        Contact,
                                        ContactOperations.Approve);

                if (!canApprove.Succeeded)
                {
                    Contact.Status = ContactStatus.Submitted;
                }
            }

            await Context.SaveChangesAsync();

            return RedirectToPage("./Index");
        }
    }
}
"@ | Set-Content .\Pages\Contacts\Edit.cshtml.cs
# ----------------------------------------------------------------------
git add .
git commit --message 'Update Pages\Contacts\Edit.cshtml.cs'
# ----------------------------------------------------------------------
# Update the DeleteModel
# https://docs.microsoft.com/en-us/aspnet/core/security/authorization/secure-data?view=aspnetcore-5.0#update-the-deletemodel
# ----------------------------------------------------------------------
@"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using ContactManager.Data;
using ContactManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using ContactManager.Authorization;

namespace ContactManager.Pages.Contacts
{
    public class DeleteModel : DI_BasePageModel
    {
        public DeleteModel(
            ApplicationDbContext context, 
            IAuthorizationService authorizationService, 
            UserManager<IdentityUser> userManager)

            : base(context, authorizationService, userManager)
        {
        }

        [BindProperty]
        public Contact Contact { get; set; }

        public async Task<IActionResult> OnGetAsync(int id)
        {
            Contact = await Context.Contact.FirstOrDefaultAsync(m => m.ContactId == id);

            if (Contact == null)
            {
                return NotFound();
            }

            var isAuthorized = await AuthorizationService.AuthorizeAsync(
                                                     User, Contact,
                                                     ContactOperations.Delete);
            if (!isAuthorized.Succeeded)
            {
                return Forbid();
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(int id)
        {
            var contact = await Context
                .Contact.AsNoTracking()
                .FirstOrDefaultAsync(m => m.ContactId == id);

            if (contact == null)
            {
                return NotFound();
            }

            var isAuthorized = await AuthorizationService.AuthorizeAsync(
                                                     User, contact,
                                                     ContactOperations.Delete);
            if (!isAuthorized.Succeeded)
            {
                return Forbid();
            }

            Context.Contact.Remove(contact);
            await Context.SaveChangesAsync();

            return RedirectToPage("./Index");
        }
    }
}

"@ | Set-Content .\Pages\Contacts\Delete.cshtml.cs
# ----------------------------------------------------------------------
git add .
git commit --message 'Update Pages\Contacts\Delete.cshtml.cs'
# ----------------------------------------------------------------------
# Inject the authorization service into the views
# https://docs.microsoft.com/en-us/aspnet/core/security/authorization/secure-data?view=aspnetcore-5.0#inject-the-authorization-service-into-the-views
# ----------------------------------------------------------------------
@"
@using Microsoft.AspNetCore.Identity
@using Microsoft.AspNetCore.Authorization

@using ContactManager
@using ContactManager.Data
@using ContactManager.Authorization
@using ContactManager.Models

@namespace ContactManager.Pages

@addTagHelper *, Microsoft.AspNetCore.Mvc.TagHelpers

@inject IAuthorizationService AuthorizationService
"@ | Set-Content .\Pages\_ViewImports.cshtml
# ----------------------------------------------------------------------
git add .
git commit --message 'Update Pages\_ViewImports.cshtml'
# ----------------------------------------------------------------------
$file = '.\Pages\Contacts\Index.cshtml'

$original_text = @"
            <th>
                @Html.DisplayNameFor(model => model.Contact[0].Email)
            </th>
"@

$replacement_text = @"
            <th>
                @Html.DisplayNameFor(model => model.Contact[0].Email)
            </th>
            <th>
                @Html.DisplayNameFor(model => model.Contact[0].Status)
            </th>
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
$file = '.\Pages\Contacts\Index.cshtml'

$original_text = @"
            <td>
                <a asp-page="./Edit" asp-route-id="@item.ContactId">Edit</a> |
                <a asp-page="./Details" asp-route-id="@item.ContactId">Details</a> |
                <a asp-page="./Delete" asp-route-id="@item.ContactId">Delete</a>
            </td>
"@

$replacement_text = @"
            <td>
                @Html.DisplayFor(modelItem => item.Status)
            </td>
            <td>
                @if ((await AuthorizationService.AuthorizeAsync(User, item, ContactOperations.Update)).Succeeded)
                {
                    <a asp-page="./Edit" asp-route-id="@item.ContactId">Edit</a>
                    <text> | </text>
                }

                <a asp-page="./Details" asp-route-id="@item.ContactId">Details</a>

                @if ((await AuthorizationService.AuthorizeAsync(User, item, ContactOperations.Delete)).Succeeded)
                {
                    <text> | </text>
                    <a asp-page="./Delete" asp-route-id="@item.ContactId">Delete</a>
                }
            </td>
"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
git add .
git commit --message 'Update Pages\Contacts\Index.cshtml'
# ----------------------------------------------------------------------
# Update Details
# https://docs.microsoft.com/en-us/aspnet/core/security/authorization/secure-data?view=aspnetcore-5.0#update-details
# ----------------------------------------------------------------------
$file = '.\Pages\Contacts\Details.cshtml'

$original_text = @"
        <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.Contact.Email)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.Contact.Email)
        </dd>
    </dl>
</div>
<div>
    <a asp-page="./Edit" asp-route-id="@Model.Contact.ContactId">Edit</a> |
    <a asp-page="./Index">Back to List</a>
</div>

"@

$replacement_text = @"
        <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.Contact.Email)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.Contact.Email)
        </dd>
        <dt>
            @Html.DisplayNameFor(model => model.Contact.Status)
        </dt>
        <dd>
            @Html.DisplayFor(model => model.Contact.Status)
        </dd>
    </dl>
</div>

@if (Model.Contact.Status != ContactStatus.Approved)
{
    @if ((await AuthorizationService.AuthorizeAsync(User, Model.Contact, ContactOperations.Approve)).Succeeded)
    {
        <form style="display:inline;" method="post">
            <input type="hidden" name="id" value="@Model.Contact.ContactId" />
            <input type="hidden" name="status" value="@ContactStatus.Approved" />
            <button type="submit" class="btn btn-xs btn-success">Approve</button>
        </form>
    }
}

@if (Model.Contact.Status != ContactStatus.Rejected)
{
    @if ((await AuthorizationService.AuthorizeAsync(User, Model.Contact, ContactOperations.Reject)).Succeeded)
    {
        <form style="display:inline;" method="post">
            <input type="hidden" name="id" value="@Model.Contact.ContactId" />
            <input type="hidden" name="status" value="@ContactStatus.Rejected" />
            <button type="submit" class="btn btn-xs btn-success">Reject</button>
        </form>
    }
}

<div>
    @if ((await AuthorizationService.AuthorizeAsync(User, Model.Contact, ContactOperations.Update)).Succeeded)
    {
        <a asp-page="./Edit" asp-route-id="@Model.Contact.ContactId">Edit</a>
        <text> | </text>
    }
    <a asp-page="./Index">Back to List</a>
</div>


"@

Edit $file -Replacing $original_text -With $replacement_text
# ----------------------------------------------------------------------
git add .
git commit --message 'Update Pages\Contacts\Details.cshtml'
# ----------------------------------------------------------------------
# Update the details page model

@"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using ContactManager.Data;
using ContactManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using ContactManager.Authorization;

namespace ContactManager.Pages.Contacts
{
    public class DetailsModel : DI_BasePageModel
    {
        public DetailsModel(
            ApplicationDbContext context,
            IAuthorizationService authorizationService,
            UserManager<IdentityUser> userManager)

            : base(context, authorizationService, userManager) 
        { }

        public Contact Contact { get; set; }

        public async Task<IActionResult> OnGetAsync(int id)
        {
            Contact = await Context.Contact.FirstOrDefaultAsync(contact => contact.ContactId == id);

            if (Contact == null)
                return NotFound();

            var isAuthorized = User.IsInRole(Constants.ContactManagersRole) || User.IsInRole(Constants.ContactAdministratorsRole);

            var currentUserId = UserManager.GetUserId(User);

            if (!isAuthorized && currentUserId != Contact.OwnerID && Contact.Status != ContactStatus.Approved)
                return Forbid();

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(int id, ContactStatus status)
        {
            var contact = await Context.Contact.FirstOrDefaultAsync(contact => contact.ContactId == id);

            if (contact == null)
                return NotFound();
            
            var contactOperation = (status == ContactStatus.Approved) ? ContactOperations.Approve : ContactOperations.Reject;

            var isAuthorized = await AuthorizationService.AuthorizeAsync(User, contact, contactOperation);

            if (!isAuthorized.Succeeded)
                return Forbid();
            
            contact.Status = status;

            Context.Contact.Update(contact);

            await Context.SaveChangesAsync();

            return RedirectToPage("./Index");
        }
    }
}
"@ | Set-Content .\Pages\Contacts\Details.cshtml.cs
# ----------------------------------------------------------------------
git add .
git commit --message 'Update Pages\Contacts\Details.cshtml.cs'
# ----------------------------------------------------------------------
# Get-Content C:\Users\dharm\AppData\Roaming\Microsoft\UserSecrets\aspnet-ContactManager-B740CA51-8183-4457-BDFC-7DDD0E3EAD0A\secrets.json

