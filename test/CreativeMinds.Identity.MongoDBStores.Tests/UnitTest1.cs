using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;
using System;
using System.Linq;
using Xunit;

namespace CreativeMinds.Identity.MongoDBStores.Tests {

	public class UnitTest1 {
		private const String mongoUrl = "mongodb://localhost/test";

		private static UserStore<MockUser, MockRole, MockUserToken> GetUserStore() {
			MongoUrl url = new MongoUrl(mongoUrl);
			IMongoClient client = new MongoClient(url);
			IMongoDatabase database = client.GetDatabase(url.DatabaseName);
			IMongoCollection<MockUser> users = database.GetCollection<MockUser>("user");
			IMongoCollection<MockRole> roles = database.GetCollection<MockRole>("role");

			return new UserStore<MockUser, MockRole, MockUserToken>(users, roles);
		}

		[Fact]
		public void CreateUser() {
			UserStore<MockUser, MockRole, MockUserToken> userStore = GetUserStore();
			IdentityResult result = userStore.CreateAsync(new MockUser { Email = "test1@test.com", UserName = "MisterTest", PasswordHash = "" }, new System.Threading.CancellationToken()).Result;

			Assert.True(result.Succeeded == true);
		}

		[Fact]
		public void FetchUser() {
			UserStore<MockUser, MockRole, MockUserToken> userStore = GetUserStore();
			String emailAddress = "test2@test.com";
			var user = new MockUser { Email = emailAddress, UserName = "MisterTest", PasswordHash = "" };
			IdentityResult result = userStore.CreateAsync(user, new System.Threading.CancellationToken()).Result;

			Assert.True(result.Succeeded == true);

			var users = userStore.Users.ToList();
			var usr =  users.FirstOrDefault(u => u.Email == emailAddress);

			user = userStore.FindByEmailAsync(usr.NormalizedEmail, new System.Threading.CancellationToken()).Result;

			Assert.NotNull(user);
		}
	}
}
