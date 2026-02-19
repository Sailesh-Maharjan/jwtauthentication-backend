using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.DataAccessLayer.Configuration
{
    public class RateLimitingSettings
    {
        public int LoginAttemptsPerMin { get; set; } = 10;
        public int LoginAttemptsPerhour { get; set; } = 20;
        public int ApiCallsPerMin { get; set; } = 50;
        public int LockoutDurationMin { get; set; } = 10;
        public int MaxFailedAttempts { get; set; } = 5; 
    }
}
