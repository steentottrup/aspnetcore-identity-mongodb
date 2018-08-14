using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Driver;
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace CreativeMinds.Identity.MongoDBStores {

	public class UserStore<TUser, TRole, TUserToken> :
		IUserRoleStore<TUser>,
		IUserStore<TUser>,
		IDisposable,
		IUserLoginStore<TUser>,
		IUserClaimStore<TUser>,
		IUserPasswordStore<TUser>,
		IUserSecurityStampStore<TUser>,
		IUserEmailStore<TUser>,
		IUserLockoutStore<TUser>,
		IUserPhoneNumberStore<TUser>,
		IQueryableUserStore<TUser>,
		IUserTwoFactorStore<TUser>,
		IUserAuthenticationTokenStore<TUser>,
		IUserAuthenticatorKeyStore<TUser>,
		IUserTwoFactorRecoveryCodeStore<TUser>
		where TUser : MongoDBIdentityUser
		where TRole : MongoDBIdentityRole
		where TUserToken : IdentityUserToken<ObjectId>, new() {

		private readonly IMongoCollection<TUser> userCollection;
		private readonly IMongoCollection<TRole> roleCollection;

		private const String internalLoginProvider = "users";
		private const String authenticatorKeyTokenName = "AuthenticatorKey";
		private const String recoveryCodeTokenName = "RecoveryCodes";

		public UserStore(IMongoCollection<TUser> userCollection, IMongoCollection<TRole> roleCollection, IdentityErrorDescriber describer = null) {

			this.userCollection = userCollection;
			this.roleCollection = roleCollection;
		}

		public virtual IQueryable<TUser> Users => this.userCollection.AsQueryable();

		public virtual Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			if (claims == null) {
				throw new ArgumentNullException(nameof(claims));
			}
			List<IdentityUserClaim> newList = new List<IdentityUserClaim>(user.Claims);
			newList.AddRange(claims.Select(c => new IdentityUserClaim(c)));
			user.Claims = newList;

			//UpdateDefinition<TUser> update = Builders<TUser>.Update.Set(u => u.Claims, newList);

			//// TODO: Test result?!?!
			//UpdateResult result = this.userCollection.UpdateOne(u => u.Id == user.Id, update, cancellationToken: cancellationToken);

			return Task.CompletedTask;
		}

		public virtual Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			if (login == null) {
				throw new ArgumentNullException(nameof(login));
			}
			List<IdentityUserLogin> newList = new List<IdentityUserLogin>(user.Logins);
			newList.Add(new IdentityUserLogin(login.LoginProvider, login.ProviderKey, login.ProviderDisplayName));
			user.Logins = newList;

			//UpdateDefinition<TUser> update = Builders<TUser>.Update.Set(u => u.Logins, newList);

			//// TODO: Test result?!?!
			//UpdateResult result = this.userCollection.UpdateOne(u => u.Id == user.Id, update, cancellationToken: cancellationToken);

			return Task.CompletedTask;
		}

		public async virtual Task AddToRoleAsync(TUser user, String normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			if (string.IsNullOrWhiteSpace(normalizedRoleName)) {
				throw new ArgumentException(nameof(normalizedRoleName));
			}

			TRole roleEntity = await this.FindRoleAsync(normalizedRoleName, cancellationToken);
			if (roleEntity == null) {
				throw new InvalidOperationException();
			}

			List<UserRole> newList = new List<UserRole>(user.Roles);
			newList.Add(new UserRole { RoleId = roleEntity.Id, Name = roleEntity.Name });
			user.Roles = newList;
		}

		public virtual async Task<Int32> CountCodesAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}

			String mergedCodes = await this.GetTokenAsync(user, internalLoginProvider, recoveryCodeTokenName, cancellationToken) ?? "";
			if (mergedCodes.Length > 0) {
				return mergedCodes.Split(';').Length;
			}

			return 0;
		}

		public virtual async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}

			await this.userCollection.InsertOneAsync(user, cancellationToken: cancellationToken);
			return IdentityResult.Success;
		}

		public virtual async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			DeleteResult result = await this.userCollection.DeleteOneAsync(u => u.Id == user.Id, cancellationToken);
			return result.DeletedCount == 1 ? IdentityResult.Success : IdentityResult.Failed();
		}

		public void Dispose() { }

		public virtual Task<TUser> FindByEmailAsync(String normalizedEmail, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			return this
					.userCollection.Find(u => u.NormalizedEmail == normalizedEmail)
					.SingleOrDefaultAsync(cancellationToken);
		}

		public virtual Task<TUser> FindByIdAsync(String userId, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			ObjectId id;
			if (ObjectId.TryParse(userId, out id)) {
				return this
						.userCollection.Find(u => u.Id == id)
						.SingleOrDefaultAsync(cancellationToken);
			}

			return null;
		}

		public virtual Task<TUser> FindByLoginAsync(String loginProvider, String providerKey, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			FilterDefinition<TUser> filter = Builders<TUser>.Filter.And(
					Builders<TUser>.Filter.Eq($"{MongoDBIdentityUser.FieldNames.Logins}.{IdentityUserLogin.FieldNames.LoginProvider}", loginProvider),
					Builders<TUser>.Filter.Eq($"{MongoDBIdentityUser.FieldNames.Logins}.{IdentityUserLogin.FieldNames.ProviderKey}", providerKey)
				);

			return this
				.userCollection.Find(filter)
					.SingleOrDefaultAsync(cancellationToken);
		}

		public virtual Task<TUser> FindByNameAsync(String normalizedUserName, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			return this
					.userCollection.Find(u => u.NormalizedUserName == normalizedUserName)
					.SingleOrDefaultAsync(cancellationToken);
		}

		public virtual Task<Int32> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}

			return Task.FromResult(user.AccessFailedCount);
		}

		public virtual Task<String> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken)
			=> this.GetTokenAsync(user, internalLoginProvider, authenticatorKeyTokenName, cancellationToken);


		public virtual async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}

			return user.Claims.Select(cl => new Claim(cl.ClaimType, cl.ClaimValue)).ToList();
		}

		public virtual Task<String> GetEmailAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			return Task.FromResult(user.Email);
		}

		public virtual Task<Boolean> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			return Task.FromResult(user.EmailConfirmed);
		}

		public virtual Task<Boolean> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			return Task.FromResult(user.LockoutEnabled);
		}

		public virtual Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			return Task.FromResult(user.LockoutEndDateUtc.HasValue ? new DateTimeOffset(user.LockoutEndDateUtc.Value) : default(DateTimeOffset?));
		}

		public virtual async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}

			return user.Logins.Select(ul => new UserLoginInfo(ul.LoginProvider, ul.ProviderKey, ul.ProviderDisplayName)).ToList();
		}

		public virtual Task<String> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			return Task.FromResult(user.NormalizedEmail);
		}

		public virtual Task<String> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			return Task.FromResult(user.NormalizedUserName);
		}

		public virtual Task<String> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			return Task.FromResult(user.PasswordHash);
		}

		public virtual Task<String> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			return Task.FromResult(user.PhoneNumber);
		}

		public virtual Task<Boolean> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			return Task.FromResult(user.PhoneNumberConfirmed);
		}

		public virtual async Task<IList<String>> GetRolesAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			return user.Roles.Select(r => r.Name).ToList();
		}

		public virtual Task<String> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			return Task.FromResult(user.SecurityStamp);
		}

		public virtual async Task<String> GetTokenAsync(TUser user, String loginProvider, String name, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			var entry = await FindTokenAsync(user, loginProvider, name, cancellationToken);
			return entry?.Value;
		}

		public virtual Task<Boolean> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			return Task.FromResult(user.TwoFactorEnabled);
		}

		public virtual Task<String> GetUserIdAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			return Task.FromResult(user.Id.ToString());
		}

		public virtual Task<String> GetUserNameAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			return Task.FromResult(user.UserName);
		}

		public virtual async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			if (claim == null) {
				throw new ArgumentNullException(nameof(claim));
			}

			return await this.userCollection
				.Find(u => u.Claims.Any(c => c.ClaimType == claim.Type && c.ClaimValue == claim.Value) == true)
				.ToListAsync();
		}

		public virtual async Task<IList<TUser>> GetUsersInRoleAsync(String normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			TRole role = await this.FindRoleAsync(normalizedRoleName, cancellationToken);

			if (role == null) {
				return new List<TUser>();
			}

			return await this.userCollection
				.Find(u => u.Roles.Any(r => r.RoleId == role.Id) == true)
				.ToListAsync();
		}

		public virtual Task<Boolean> HasPasswordAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();
			return Task.FromResult(user.PasswordHash != null);
		}

		public virtual Task<Int32> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			user.AccessFailedCount++;
			return Task.FromResult(user.AccessFailedCount);
		}

		public virtual async Task<Boolean> IsInRoleAsync(TUser user, String normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			TRole role = await this.FindRoleAsync(normalizedRoleName, cancellationToken);
			if (role == null) {
				return false;
			}

			return user.Roles.Any(r => r.RoleId == role.Id);
		}

		public virtual async Task<Boolean> RedeemCodeAsync(TUser user, String code, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			if (code == null) {
				throw new ArgumentNullException(nameof(code));
			}

			var mergedCodes = await this.GetTokenAsync(user, internalLoginProvider, recoveryCodeTokenName, cancellationToken) ?? "";
			var splitCodes = mergedCodes.Split(';');
			if (splitCodes.Contains(code)) {
				var updatedCodes = new List<string>(splitCodes.Where(s => s != code));
				await ReplaceCodesAsync(user, updatedCodes, cancellationToken);
				return true;
			}
			return false;
		}

		public virtual Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			if (claims == null) {
				throw new ArgumentNullException(nameof(claims));
			}

			List<IdentityUserClaim> newList = new List<IdentityUserClaim>(user.Claims);
			foreach (Claim claim in claims) {
				if (newList.Any(c => c.ClaimValue == claim.Value && c.ClaimType == claim.Type)) {
					IEnumerable<IdentityUserClaim> userClaims = newList.Where(c => c.ClaimValue == claim.Value && c.ClaimType == claim.Type);
					foreach (IdentityUserClaim uc in userClaims) {
						newList.Remove(uc);
					}
				}
			}

			return Task.CompletedTask;
		}

		public virtual async Task RemoveFromRoleAsync(TUser user, String normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			if (String.IsNullOrWhiteSpace(normalizedRoleName)) {
				throw new ArgumentException(nameof(normalizedRoleName));
			}

			TRole roleEntity = await this.FindRoleAsync(normalizedRoleName, cancellationToken);
			if (roleEntity != null) {
				UserRole userRole = user.Roles.SingleOrDefault(r => r.RoleId == roleEntity.Id);
				if (userRole != null) {
					List<UserRole> newList = new List<UserRole>(user.Roles);
					newList.Remove(userRole);
					user.Roles = newList;
				}
			}
		}

		public virtual async Task RemoveLoginAsync(TUser user, String loginProvider, String providerKey, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}

			IdentityUserLogin entry = await this.FindUserLoginAsync(user.Id, loginProvider, providerKey, cancellationToken);
			if (entry != null) {
				List<IdentityUserLogin> newList = new List<IdentityUserLogin>(user.Logins);
				newList.Remove(entry);
				user.Logins = newList;
			}
		}

		public virtual async Task RemoveTokenAsync(TUser user, String loginProvider, String name, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			var entry = await this.FindTokenAsync(user, loginProvider, name, cancellationToken);
			if (entry != null) {
				await this.RemoveUserTokenAsync(entry);
			}
		}

		public virtual Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			if (claim == null) {
				throw new ArgumentNullException(nameof(claim));
			}
			if (newClaim == null) {
				throw new ArgumentNullException(nameof(newClaim));
			}

			foreach (IdentityUserClaim matchedClaim in user.Claims) {
				matchedClaim.ClaimValue = newClaim.Value;
				matchedClaim.ClaimType = newClaim.Type;
			}

			return Task.CompletedTask;
		}

		public virtual Task ReplaceCodesAsync(TUser user, IEnumerable<String> recoveryCodes, CancellationToken cancellationToken) {
			var mergedCodes = String.Join(";", recoveryCodes);
			return SetTokenAsync(user, internalLoginProvider, recoveryCodeTokenName, mergedCodes, cancellationToken);
		}

		public virtual Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			user.AccessFailedCount = 0;
			return Task.CompletedTask;
		}

		public virtual Task SetAuthenticatorKeyAsync(TUser user, String key, CancellationToken cancellationToken)
			=> SetTokenAsync(user, internalLoginProvider, authenticatorKeyTokenName, key, cancellationToken);

		public virtual Task SetEmailAsync(TUser user, String email, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			user.Email = email;
			return Task.CompletedTask;
		}

		public virtual Task SetEmailConfirmedAsync(TUser user, Boolean confirmed, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			user.EmailConfirmed = confirmed;
			return Task.CompletedTask;
		}

		public virtual Task SetLockoutEnabledAsync(TUser user, Boolean enabled, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			user.LockoutEnabled = enabled;
			return Task.CompletedTask;
		}

		public virtual Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			user.LockoutEndDateUtc = lockoutEnd.HasValue ? lockoutEnd.Value.UtcDateTime : default(DateTime?);
			return Task.CompletedTask;
		}

		public virtual Task SetNormalizedEmailAsync(TUser user, String normalizedEmail, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			user.NormalizedEmail = normalizedEmail;
			return Task.CompletedTask;
		}

		public virtual Task SetNormalizedUserNameAsync(TUser user, String normalizedName, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			user.NormalizedUserName = normalizedName;
			return Task.CompletedTask;
		}

		public virtual Task SetPasswordHashAsync(TUser user, String passwordHash, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			user.PasswordHash = passwordHash;
			return Task.CompletedTask;
		}

		public virtual Task SetPhoneNumberAsync(TUser user, String phoneNumber, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			user.PhoneNumber = phoneNumber;
			return Task.CompletedTask;
		}

		public virtual Task SetPhoneNumberConfirmedAsync(TUser user, Boolean confirmed, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			user.PhoneNumberConfirmed = confirmed;
			return Task.CompletedTask;
		}

		public virtual Task SetSecurityStampAsync(TUser user, String stamp, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			if (stamp == null) {
				throw new ArgumentNullException(nameof(stamp));
			}
			user.SecurityStamp = stamp;
			return Task.CompletedTask;
		}

		public virtual async Task SetTokenAsync(TUser user, String loginProvider, String name, String value, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}

			IdentityUserToken token = await this.FindTokenAsync(user, loginProvider, name, cancellationToken);
			if (token == null) {
				await this.AddUserTokenAsync(this.CreateUserToken(user, loginProvider, name, value));
			}
			else {
				token.Value = value;
			}
		}

		protected virtual IdentityUserToken CreateUserToken(TUser user, String loginProvider, String name, String value) {
			return new IdentityUserToken {
				UserId = user.Id,
				LoginProvider = loginProvider,
				Name = name,
				Value = value
			};
		}

		public virtual Task SetTwoFactorEnabledAsync(TUser user, Boolean enabled, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			user.TwoFactorEnabled = enabled;
			return Task.CompletedTask;
		}

		public virtual Task SetUserNameAsync(TUser user, String userName, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			if (user == null) {
				throw new ArgumentNullException(nameof(user));
			}
			user.UserName = userName;
			return Task.CompletedTask;
		}

		public virtual async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			// TODO: Log document etc!!!
			ReplaceOneResult result = await this.userCollection.ReplaceOneAsync<TUser>(u => u.Id == user.Id, user, cancellationToken: cancellationToken);
			return result.ModifiedCount == 1 ? IdentityResult.Success : IdentityResult.Failed();
		}

		protected virtual async Task AddUserTokenAsync(IdentityUserToken token) {
			TUser user = await this.FindByIdAsync(token.UserId.ToString(), CancellationToken.None);

			List<IdentityUserToken> newList = new List<IdentityUserToken>(user.Tokens);
			newList.Add(token);
			user.Tokens = newList;
		}

		protected virtual Task<TRole> FindRoleAsync(String normalizedRoleName, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			return this.roleCollection
				.Find(r => r.NormalizedName == normalizedRoleName)
				.SingleOrDefaultAsync(cancellationToken);
		}

		protected virtual Task<IdentityUserToken> FindTokenAsync(TUser user, String loginProvider, String name, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			return Task.FromResult(user.Tokens.SingleOrDefault(t => t.LoginProvider == loginProvider && t.Name == name));

			//return Task.FromResult(
			//	this
			//		.userCollection
			//		.Find(u => u.Id == user.Id && u.Tokens.Any(t => t.LoginProvider == loginProvider && t.Name == name))
			//		.SingleOrDefault()
			//		.Tokens
			//		.SingleOrDefault(t => t.LoginProvider == loginProvider && t.Name == name)
			//	);
		}

		protected virtual Task<TUser> FindUserAsync(ObjectId userId, CancellationToken cancellationToken) {
			return this.userCollection
				.Find(u => u.Id == userId)
				.SingleOrDefaultAsync(cancellationToken);
		}

		protected virtual Task<IdentityUserLogin> FindUserLoginAsync(ObjectId userId, String loginProvider, String providerKey, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			return Task.FromResult(
				this
					.userCollection
					.Find(u => u.Id == userId && u.Logins.Any(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey))
					.SingleOrDefault()
					.Logins
					.SingleOrDefault(ul => ul.LoginProvider == loginProvider && ul.ProviderKey == providerKey)
				);
		}

		protected virtual async Task<IdentityUserLogin> FindUserLoginAsync(String loginProvider, String providerKey, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			TUser user = await this
					.userCollection
					.Find(u => u.Logins.Any(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey))
					.SingleOrDefaultAsync();
			if (user == null) {
				return null;
			}

			return user.Logins
					.SingleOrDefault(ul => ul.LoginProvider == loginProvider && ul.ProviderKey == providerKey);
		}

		protected virtual Task<UserRole> FindUserRoleAsync(ObjectId userId, ObjectId roleId, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			return Task.FromResult(
				this
					.userCollection
					.Find(u => u.Id == userId && u.Roles.Any(r => r.RoleId == roleId))
					.SingleOrDefault()
					.Roles
					.SingleOrDefault(r => r.RoleId == roleId)
				);
		}

		protected virtual async Task RemoveUserTokenAsync(IdentityUserToken token) {
			TUser user = await this.FindByIdAsync(token.UserId.ToString(), CancellationToken.None);
			List<IdentityUserToken> newList = new List<IdentityUserToken>(user.Tokens);
			newList.Remove(token);
			user.Tokens = newList;
		}
	}
}
