using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using System;

namespace CreativeMinds.Identity.MongoDBStores {

	public class UserRole : IdentityUserRole<ObjectId> { }
}
