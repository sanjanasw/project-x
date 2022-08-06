using Project_X.Common.Enums;
using Project_X.Data.Models;

namespace Project_X.Helpers
{
    public class EmailTemplates
    {
#pragma warning disable CS8602 // Dereference of a possibly null reference.
        public EmailTemplate GetEmailTemplate(EmailTypes type, string inputEmail, ApplicationUser? user = null, string? token = null)
        {
            const string projectName = "Project-X";
            string subject = "";
            string html = "";
            string verifyUrl;

            try
            {
                switch (type)
                {
                    case EmailTypes.Verification:
                        verifyUrl = $"https://happy-river-0ccacfa10.1.azurestaticapps.net/auth/confirm-email?userid={user.Id}&token={token}";
                        subject = $"Sign-up Verification {projectName} - Verify Email";
                        html =
                        $@" <center><img
                                style=""width: 40%""
                                src='https://docs.google.com/uc?id=1kIvq5gRqlUM_y-Y-7KpQw3oGtuX7Im0A'
                                alt=''
                                />
                            <h2>
                                Please click the below button to <br /> verify your email
                            </h2>
                            <br />
                                <a
                                style=""
                                    border-radius: 5px;
                                    color: white;
                                    background-color: rgb(4, 128, 201);
                                    padding: 15px;
                                    border: none;
                                    letter-spacing: 0.1rem;
                                    text-transform: uppercase;
                                    text-decoration: none;
                                ""
                                href=""{verifyUrl}""
                                >
                                Verify email
                                </a></center>";
                        break;
                    case EmailTypes.ResetPassword:
                        verifyUrl = $"https://happy-river-0ccacfa10.1.azurestaticapps.net/auth/reset-password?userid={user.Id}&token={token}";
                        subject = $"{projectName} - Reset password";
                        html = $@" <center>
                                <img
                                style=""width: 40%""
                                src='https://docs.google.com/uc?id=12MmOUkndXs65qf7kd6FCzV4iZGKPF16s'
                                alt=''
                                />
                            <h2 style=""
                                    color: black;
                                "">
                                Please click the below button to <br />
                                reset your password
                            </h2>
                            <br />
                                <a
                                style=""
                                    border-radius: 5px;
                                    color: white;
                                    background-color: rgb(255, 115, 0);
                                    padding: 15px;
                                    border: none;
                                    letter-spacing: 0.1rem;
                                    text-transform: uppercase;
                                    text-decoration: none;
                                ""
                                href=""{verifyUrl}""
                                >
                                Reset Password
                                </a>
                            </center>";
                        break;
                    case EmailTypes.Verified:
                        subject = $"Sign-up {projectName}";
                        html =
                        $@" <center><img
                                style=""width: 40%""
                                src='https://docs.google.com/uc?id=1LqFsaoDVUdXQMUMoEZ8MkNTjDiYQp1FZ'
                                alt=''
                                />
                            <h2 style=""
                                    color: black;
                                "">
                                Your email verification is successfull
                            </h2>
                            <br />
                                <a
                                style=""
                                    border-radius: 5px;
                                    color: white;
                                    background-color: rgb(37, 199, 50);
                                    padding: 15px;
                                    border: none;
                                    letter-spacing: 0.1rem;
                                    text-transform: uppercase;
                                    text-decoration: none;
                                ""
                                href=""https://happy-river-0ccacfa10.1.azurestaticapps.net/auth/login""
                                >
                                Continue to Login
                                </a></center>";
                        break;
                    case EmailTypes.PasswordResetSuccess:
                        subject = "Password Reset Successfull";
                        html =
                        $@" <center>
                                <img
                                style=""width: 40%""
                                src='https://docs.google.com/uc?id=1tQNONuwfg5phj1teyBbG7W02lpQ6nPBi'
                                alt=''
                                />
                            <h2>
                                Password Resetted Successfully!
                            </h2>
                            <br />
                                <a
                                style=""
                                    border-radius: 5px;
                                    color: white;
                                    background-color: rgb(143, 179, 46);
                                    padding: 15px;
                                    border: none;
                                    letter-spacing: 0.1rem;
                                    text-transform: uppercase;
                                    text-decoration: none;
                                ""
                                href=""https://happy-river-0ccacfa10.1.azurestaticapps.net/auth/login""
                                >
                                Continue to Login
                                </a>
                            </center>";
                        break;
                    case EmailTypes.NewUser:
                        verifyUrl = $"https://happy-river-0ccacfa10.1.azurestaticapps.net/auth/new-user-setup?userid={user.Id}&token={token}";
                        subject = $"{projectName} - New User Invitation";
                        html =
                        $@" <center>
                                <img
                                style=""width: 40%""
                                src='https://docs.google.com/uc?id=1ornFZghAE9F3kNLxmMYNo5F9H0azVKU3'
                                alt=''
                                />
                            <h2>
                                New User Setup
                            </h2>
                            <br />
                                <a
                                style=""
                                    border-radius: 5px;
                                    color: white;
                                    background-color: rgb(179, 80, 204);
                                    padding: 15px;
                                    border: none;
                                    letter-spacing: 0.1rem;
                                    text-transform: uppercase;
                                    text-decoration: none;
                                ""
                                href=""{verifyUrl}""
                                >
                                Continue to Login
                                </a>
                            </center>";
                        break;
                    case EmailTypes.NewUserSetupSuccess:
                        subject = "Password Setup Successfull";
                        html =
                        $@" <center>
                                <img
                                style=""width: 40%""
                                src='https://docs.google.com/uc?id=1GhZJQfcGeJhxZ0_kPh2MrfSMe9izMsi-'
                                alt=''
                                />
                            <h2>
                                Password of new user account <br />
                                setup successfully!
                            </h2>
                            <br />
                                <a
                                style=""
                                    border-radius: 5px;
                                    color: white;
                                    background-color: rgb(104, 107, 109);
                                    padding: 15px;
                                    border: none;
                                    letter-spacing: 0.1rem;
                                    text-transform: uppercase;
                                    text-decoration: none;
                                ""
                                href=""https://happy-river-0ccacfa10.1.azurestaticapps.net/auth/login""
                                >
                                Continue to Login
                                </a>
                        </center>";
                        break;
                    case EmailTypes.PasswordChanged:
                        subject = "Password Change Successfull";
                        html =
                        $@" <center><img
                                style=""width: 40%""
                                src='https://docs.google.com/uc?id=10uumtpFjMuE7CIXYiQjeKmNPMIhr1YkX'
                                alt=''
                                />
                            <h2>
                                Password change successfull!
                            </h2>
                            <br />
                                <a
                                style=""
                                    border-radius: 5px;
                                    color: white;
                                    background-color: rgba(245, 55, 91, 1);
                                    padding: 15px;
                                    border: none;
                                    letter-spacing: 0.1rem;
                                    text-transform: uppercase;
                                    text-decoration: none;
                                ""
                                href=""https://happy-river-0ccacfa10.1.azurestaticapps.net/auth/login""
                                >
                                Continue to Login
                                </a><center>";
                        break;

                }
#pragma warning restore CS8602 // Dereference of a possibly null reference.

                return new EmailTemplate()
                {
                    Email = inputEmail,
                    Subject = subject,
                    Html = html
                };
            }
            catch (Exception)
            {
                throw;
            }
        }

        public class EmailTemplate
        {
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
            public string Email { get; set; }
            public string Subject { get; set; }
            public string Html { get; set; }
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        }
    }
}