using Project_X.Common.Enums;
using Project_X.Data.Interfaces;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Project_X.Data.General
{
    public abstract class DataRecord : IDataRecord
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public virtual int Id { get; set; }
        [Required]
        public DateTime CreatedOn { get; set; } = DateTime.Now.ToUniversalTime();
        public string CreatedBy { get; set; }
        public DateTime? ModifiedOn { get; set; }
        public string ModifiedBy { get; set; }
        public DateTime? DeletedOn { get; set; }
        public string DeletedBy { get; set; }
        [Required]
        public RecordStatus Status { get; set; } = RecordStatus.Active;
    }
}
