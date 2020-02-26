using Microsoft.AspNetCore.Identity;
using System;
using System.Linq;
using Xunit;

namespace CreativeMinds.Identity.MongoDBStores.Tests {

	public class UsersWithRolesTests {

		[Fact]
		public void AddRoleToUser() {
			var stores = TestInit.GetEmptyStores();

			UserStore<MockUser, MockRole, MockUserToken> userStore = stores.Item2;
			String userName = "MisterTest";
			String emailAddress = "test1@test.com";
			IdentityResult result = userStore.CreateAsync(new MockUser { Email = emailAddress, UserName = userName, NormalizedUserName = userName.ToUpperInvariant(), NormalizedEmail = emailAddress.ToUpperInvariant() }, new System.Threading.CancellationToken()).Result;

			//var user = userStore.Users.Single();

			//var roleStore = stores.Item1;
			//String name = "FirstOne";
			//result = roleStore.CreateAsync(new MockRole { Name = name, NormalizedName = name.ToUpperInvariant() }, new System.Threading.CancellationToken()).Result;

			//var role = roleStore.Roles.Single();

			//userStore.AddToRoleAsync(user, role.NormalizedName, new System.Threading.CancellationToken()).Wait();

			//Assert.True(userStore.IsInRoleAsync(user, role.NormalizedName, new System.Threading.CancellationToken()).Result);
		}
	}
}
