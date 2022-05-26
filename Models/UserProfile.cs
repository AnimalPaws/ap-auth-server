using System;
using System.Collections.Generic;

#nullable disable

namespace ap_auth_server.Models
{
    public partial class UserProfile
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public byte[] Picture { get; set; }
        public string Biography { get; set; }
        public int? NotificationId { get; set; }
        public int? PetId { get; set; }
        public bool? EmailVerified { get; set; }
        public DateTime? UpdatedAt { get; set; }

        public virtual User User { get; set; }
    }
}
