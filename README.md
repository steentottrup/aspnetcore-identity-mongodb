CreativeMinds.Identity.MongoDBStores
====================================

More to come!

[![Build status](https://ci.appveyor.com/api/projects/status/f4rtjaeckwawfipj/branch/master?svg=true)](https://ci.appveyor.com/project/steentottrup97321/aspnetcore-identity-mongodb/branch/master)
[![NuGet Version](http://img.shields.io/nuget/v/CreativeMinds.Identity.MongoDBStores.svg?style=flat)](https://www.nuget.org/packages/CreativeMinds.Identity.MongoDBStores/)

## Instructions ##

More to come!

In your ```ConfigureServices``` method in the ```StartUp``` class, add this line:
```C#
		services.AddIdentityWithMongoStoresUsingCustomTypes<ApplicationUser, MongoDBIdentityRole>("<MongoDB connection string>", "<Name of the user collection>", "<Name of the role collection>")
```
