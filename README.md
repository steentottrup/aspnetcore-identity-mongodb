CreativeMinds.Identity.MongoDBStores
====================================

More to come!

## Instructions ##

More to come!

In your ```ConfigureServices``` method in the ```StartUp``` class, add this line:
```C#
		services.AddIdentityWithMongoStoresUsingCustomTypes<ApplicationUser, MongoDBIdentityRole>("<MongoDB connection string>", "<Name of the user collection>", "<Name of the role collection>")
```
