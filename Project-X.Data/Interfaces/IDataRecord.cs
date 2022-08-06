using Project_X.Common.Enums;

namespace Project_X.Data.Interfaces
{
    public interface IDataRecord
    {
        int Id { get; set; }
        DateTime CreatedOn { get; set; }
        string? CreatedBy { get; set; }
        DateTime? ModifiedOn { get; set; }
        string? ModifiedBy { get; set; }
        DateTime? DeletedOn { get; set; }
        string? DeletedBy { get; set; }
        RecordStatus Status { get; set; }
    }
}
