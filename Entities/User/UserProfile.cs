namespace ap_auth_server.Entities.User
{
    public class UserProfile
    {
        public int? Id { get; set; }
        public string? Picture { get; set; }
        public string? Biography { get; set; }
        public int? Notification_Id { get; set; }
        public int? Pet_Id { get; set; }
    }
}
