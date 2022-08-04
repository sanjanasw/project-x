using AutoMapper;
using Project_X.Business.ViewModels;
using Project_X.Data.Models;

namespace Project_X.Business.Mappings
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            CreateMap<ApplicationUser, UserViewModel>()
                .ForMember(
                    destination => destination.Name,
                    options => options.MapFrom(
                        source => source.FirstName + " " + source.LastName
                        )
                );
        }
    }
}
