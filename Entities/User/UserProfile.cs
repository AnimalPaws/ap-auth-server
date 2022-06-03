namespace ap_auth_server.Entities.User
{
    public class UserProfile
    {
        public int? Id { get; set; }
        public string? Picture { get; set; }
        public string? Biography { get; set; }
        public int? NotificationId { get; set; }
        public int? PetId { get; set; }
    }
}
