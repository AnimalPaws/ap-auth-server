namespace ap_auth_server.Entities.Veterinaries
{
    public class VeterinaryProfile
    {
        public int? Id { get; set; }
        public string? Picture { get; set; }
        public string? About { get; set; }
        public int? Notification_Id { get; set; }
        public int? Pet_Id { get; set; }
    }
}