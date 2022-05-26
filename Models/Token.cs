using System;
using System.Collections.Generic;

#nullable disable

namespace ap_auth_server.Models
{
    public partial class Token
    {
        public int Id { get; set; }
        public bool? IsRevoke { get; set; }
        public DateTime? CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
    }
}
