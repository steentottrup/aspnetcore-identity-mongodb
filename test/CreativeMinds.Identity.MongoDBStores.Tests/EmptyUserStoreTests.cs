using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;
using System;
using System.Linq;
using Xunit;

namespace CreativeMinds.Identity.MongoDBStores.Tests {

	public class EmptyUserStoreTests {

		[Fact]
		public void CreateUser() {
			UserStore<MockUser, MockRole, MockUserToken> userStore = TestInit.GetEmptyUserStore();
			IdentityResult result = userStore.CreateAsync(new MockUser { Email = "test1@test.com", UserName = "MisterTest", PasswordHash = "" }, new System.Threading.CancellationToken()).Result;

			Assert.True(result.Succeeded == true);
		}

		[Fact]
		public void CreateAndFetchUser() {
			UserStore<MockUser, MockRole, MockUserToken> userStore = TestInit.GetEmptyUserStore();
			String emailAddress = "test1@test.com";
			var user = new MockUser { Email = emailAddress, UserName = "MisterTest", PasswordHash = "" };
			IdentityResult result = userStore.CreateAsync(user, new System.Threading.CancellationToken()).Result;

			Assert.True(result.Succeeded == true);

			var users = userStore.Users.ToList();

			Assert.Collection(users, (ux) => {
				Assert.Equal(emailAddress, ux.Email);
			});

			var usr = users.FirstOrDefault(u => u.Email == emailAddress);

			user = userStore.FindByEmailAsync(usr.NormalizedEmail, new System.Threading.CancellationToken()).Result;

			Assert.NotNull(user);
		}
	}
}
