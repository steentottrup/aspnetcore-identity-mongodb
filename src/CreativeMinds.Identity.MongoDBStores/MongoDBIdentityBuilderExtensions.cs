using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Bson;
using MongoDB.Driver;
using System;

namespace CreativeMinds.Identity.MongoDBStores {

	public static class MongoDBIdentityBuilderExtensions {

		public static IdentityBuilder RegisterMongoStores<TUser, TRole>(this IdentityBuilder builder, String connectionString, String userCollectionName, String roleCollectionName)
			where TRole : MongoDBIdentityRole
			where TUser : MongoDBIdentityUser {

			MongoUrl url = new MongoUrl(connectionString);
			IMongoClient client = new MongoClient(url);
			if (url.DatabaseName == null) {
				throw new ArgumentException("The connection string must contain a database name", connectionString);
			}
			IMongoDatabase database = client.GetDatabase(url.DatabaseName);
			return builder.RegisterMongoStores(
				p => database.GetCollection<TUser>(userCollectionName),
				p => database.GetCollection<TRole>(roleCollectionName));
		}

		public static IdentityBuilder RegisterMongoStores<TUser, TRole>(this IdentityBuilder builder,
					Func<IServiceProvider, IMongoCollection<TUser>> usersCollectionFactory,
					Func<IServiceProvider, IMongoCollection<TRole>> rolesCollectionFactory)
					where TRole : MongoDBIdentityRole
					where TUser : MongoDBIdentityUser {

			if (typeof(TUser) != builder.UserType) {
				var message = "User type passed to RegisterMongoStores must match user type passed to AddIdentity. "
							  + $"You passed {builder.UserType} to AddIdentity and {typeof(TUser)} to RegisterMongoStores, "
							  + "these do not match.";
				throw new ArgumentException(message);
			}
			if (typeof(TRole) != builder.RoleType) {
				var message = "Role type passed to RegisterMongoStores must match role type passed to AddIdentity. "
							  + $"You passed {builder.RoleType} to AddIdentity and {typeof(TRole)} to RegisterMongoStores, "
							  + "these do not match.";
				throw new ArgumentException(message);
			}

			// The MongoDB driver does not take up ay ressources that needs to be disposed from request to request, so Singleton
			builder.Services.AddScoped<IUserStore<TUser>>(p => new UserStore<TUser, TRole, IdentityUserToken>(usersCollectionFactory(p), rolesCollectionFactory(p)));
			builder.Services.AddScoped<IRoleStore<TRole>>(p => new RoleStore<TRole, ObjectId, IdentityUserRole<ObjectId>, IdentityRoleClaim>(rolesCollectionFactory(p)));
			return builder;
		}

		public static IdentityBuilder AddIdentityWithMongoStores(this IServiceCollection services, String connectionString) {
			return services.AddIdentityWithMongoStoresUsingCustomTypes<MongoDBIdentityUser, MongoDBIdentityRole>(connectionString);
		}

		public static IdentityBuilder AddIdentityWithMongoStoresUsingCustomTypes<TUser, TRole>(this IServiceCollection services, String connectionString)
			where TUser : MongoDBIdentityUser
			where TRole : MongoDBIdentityRole {
			return services.AddIdentity<TUser, TRole>()
				.RegisterMongoStores<TUser, TRole>(connectionString, "users", "roles");
		}

		public static IdentityBuilder AddIdentityWithMongoStoresUsingCustomTypes<TUser, TRole>(this IServiceCollection services, String connectionString, String userCollectionName, String roleCollectionName)
			where TUser : MongoDBIdentityUser
			where TRole : MongoDBIdentityRole {
			return services.AddIdentity<TUser, TRole>()
				.RegisterMongoStores<TUser, TRole>(connectionString, userCollectionName, roleCollectionName);
		}
	}
}
