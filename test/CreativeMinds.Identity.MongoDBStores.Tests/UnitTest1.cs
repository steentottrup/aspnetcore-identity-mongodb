using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;
using System;
using Xunit;

namespace CreativeMinds.Identity.MongoDBStores.Tests {

	public class UnitTest1 {
		private const String mongoUrl = "mongodb://localhost/test";

		[Fact]
		public void Test1() {
			MongoUrl url = new MongoUrl(mongoUrl);
			IMongoClient client = new MongoClient(url);
			IMongoDatabase database = client.GetDatabase(url.DatabaseName);
			IMongoCollection<MockUser> users = database.GetCollection<MockUser>("user");
			IMongoCollection<MockRole> roles = database.GetCollection<MockRole>("role");

			UserStore<MockUser, MockRole, MockUserToken> userStore = new UserStore<MockUser, MockRole, MockUserToken>(users, roles);
			IdentityResult result = userStore.CreateAsync(new MockUser { Email = "test@test.com", UserName = "MisterTest", PasswordHash = "" }, new System.Threading.CancellationToken()).Result;

			Assert.True(result.Succeeded == true);
		}
	}
}
