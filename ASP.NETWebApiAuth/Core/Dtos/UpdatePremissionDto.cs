using System.ComponentModel.DataAnnotations;

namespace ASP.NETWebApiAuth.Core.Dtos
{
    public class UpdatePremissionDto
    {
        [Required(ErrorMessage = "UserName is required")]
        public string UserName { get; set; }
    }
}
