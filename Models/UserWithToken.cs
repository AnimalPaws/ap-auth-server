namespace ap_auth_server.Models
{
    public class UserWithToken : User
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }

        public UserWithToken(User user)
        {
            this.Id = user.Id;
            this.FirstName = user.FirstName;
            this.MiddleName = user.MiddleName;
            this.Surname = user.Surname;
            this.LastName = user.LastName;
            this.Sex = user.Sex;
            this.Email = user.Email;
            this.Password = user.Password;
            this.PhoneNumber = user.PhoneNumber;
            this.Birthdate = user.Birthdate;
            this.Department = user.Department;
            this.City = user.City;
            this.PhoneNumberVerified = user.PhoneNumberVerified;
            this.IsBlocked = user.IsBlocked;
            this.IsRestricted = user.IsRestricted;
            this.CreatedAt = user.CreatedAt;
            this.ProfileId = user.ProfileId;
        }
    }
}