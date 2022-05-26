using System;
using System.Collections.Generic;

#nullable disable

namespace ap_auth_server.Models
{
    public partial class FoundationProfile
    {
        public int Id { get; set; }
        public byte[] Picture { get; set; }
        public string About { get; set; }
        public int? NotificationId { get; set; }
        public int? PetId { get; set; }
        public DateTime? UpdatedAt { get; set; }

        public virtual Foundation Foundation { get; set; }
    }
}
