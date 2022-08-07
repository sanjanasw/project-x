﻿using AutoMapper;
using Project_X.Business.ViewModels;
using Project_X.Common.Enums;
using Project_X.Data.Models;

namespace Project_X.Business.Mappings
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {

            CreateMap<RegisterViewModel, ApplicationUser>();

            CreateMap<ApplicationUserViewModel, UserViewModel>()
                .ForMember(
                    destination => destination.Id,
                    options => options.MapFrom(
                        source => source.ApplicationUser.Id
                        )
                )
                .ForMember(
                    destination => destination.Email,
                    options => options.MapFrom(
                        source => source.ApplicationUser.Email
                        )
                )
                .ForMember(
                    destination => destination.Name,
                    options => options.MapFrom(
                        source => source.ApplicationUser.FirstName + " " + source.ApplicationUser.LastName
                        )
                )
                .ForMember(
                    destination => destination.Username,
                    options => options.MapFrom(
                        source => source.ApplicationUser.UserName
                        )
                )
                .ForMember(
                    destination => destination.Roles,
                    options => options.MapFrom(
                        source => source.Roles
                        )
                );
        }
    }
}
