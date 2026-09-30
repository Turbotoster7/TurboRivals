# String dump: NFS14.exe

- File: `D:\SteamLibrary\steamapps\common\Need for Speed(TM) Rivals\NFS14.exe`
- Size: 30,449,280 B
- Strings found (>= 4 characters): 315,292

Offsets are file positions (not RVAs) - for use in a hex editor.

## hosts (11)

_EA backend host names - the most important result. This is where we look for the redirector._

```
0x016768d0  ascii  http://elephant.online.ea.com/bugsentry
0x016768f8  ascii  https://reports.tools.gos.ea.com/bugsentry
0x016ce2a0  ascii  gosredirector.online.ea.com
0x016ce2c0  ascii  gosredirector.stest.ea.com
0x016ce2e0  ascii  gosredirector.scert.ea.com
0x016ce300  ascii  gosredirector.ea.com
0x016eab10  ascii  peach.online.ea.com
0x0170d300  ascii  demangler.ea.com
0x0170d9b0  ascii  https://gosca.ea.com:44125/redirector
0x0171b06c  ascii  For more information on 3D audio calculation and rendering, please see the EAAudio3D package documentation and library. Also, please refer to the EATech 3D Audio Solution white papers and presentation on EA Knowledge at: http://www.worldwide.ea.com/articles/view.aspx?id=2770 .
0x01d09b45  ascii  http://www.ea.com/0
```

## urls (26)

_Full URLs - HTTPS endpoints to stub out (config, telemetry, QoS)._

```
0x014e43ed  ascii   jour votre pilote sur http://www.geforce.com/drivers avant de jouer au jeu.
0x014e4480  ascii  Detected NVIDIA GeForce driver version %u.%02u. The recommended driver version is %d.%02d or later. Please update your drivers at http://www.geforce.com/drivers before playing the game.
0x014e45f5  ascii   jour votre pilote sur http://www.amd.com avant de jouer au jeu.
0x014e4670  ascii  Detected AMD Radeon driver version %d.%d. The recommended driver version is %d.%d or later. Please update your drivers at http://www.amd.com/ before playing the game.
0x0150c41f  ascii  ?http://www.w3.org/XML/1998/namespace
0x0150c450  ascii  http://www.w3.org/2000/xmlns/
0x0150c680  ascii  xml=http://www.w3.org/XML/1998/namespace
0x01548c30  ascii  http://www.needforspeed.com
0x016768b0  ascii  http://159.153.103.98/bugsentry
0x0170df40  ascii  <s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
0x0170e978  ascii  http://%s:%d/%s
0x0170e988  ascii  http://%s:%d/getPeerAddress?myIP=%s&myPort=%d&version=1.0
0x01d08832  ascii  http://ocsp.thawte.com0
0x01d0886e  ascii  .http://crl.thawte.com/ThawteTimestampingCA.crl0
0x01d08c13  ascii  http://ts-ocsp.ws.symantec.com07
0x01d08c3e  ascii  +http://ts-aia.ws.symantec.com/tss-ca-g2.cer0<
0x01d08c7c  ascii  +http://ts-crl.ws.symantec.com/tss-ca-g2.crl0(
0x01d08ea8  ascii  2Terms of use at https://www.verisign.com/rpa (c)101.0,
0x01d0914a  ascii  /http://csc3-2010-crl.verisign.com/CSC3-2010.crl0D
0x01d091a4  ascii  https://www.verisign.com/rpa0
0x01d091f3  ascii  http://ocsp.verisign.com0;
0x01d09218  ascii  /http://csc3-2010-aia.verisign.com/CSC3-2010.cer0
0x01d096e6  ascii  https://www.verisign.com/cps0*
0x01d09789  ascii  #http://logo.verisign.com/vslogo.gif04
0x01d097bf  ascii  #http://crl.verisign.com/pca3-g5.crl04
0x01d09801  ascii  http://ocsp.verisign.com0
```

## blaze (511)

_Everything that touches BlazeSDK - component names, connection states, errors._

```
0x01522b78  ascii  playerBlazeID
0x015d8b70  ascii  Blaze::Messaging::ClientMessage
0x015f9170  ascii  BlazeEnvironment
0x015f9188  ascii  BlazeServiceName
0x015f91a0  ascii  BlazeClientName
0x015f91d0  ascii  BlazeClientVersion
0x015f91e8  ascii  BlazeClientSkuId
0x015f9200  ascii  BlazeClientId
0x015f9210  ascii  BlazeClientSecret
0x015f9228  ascii  BlazeServerClientId
0x016aa040  ascii  X-BLAZE-ERRORCODE
0x016aa6e0  ascii  BlazeHub::mLoginManagers
0x016aa700  ascii  BlazeSDK
0x016ae3f8  ascii  mBlazeId
0x016ae628  ascii  mBlazeIds
0x016ae648  ascii  mBlazeUserIdOrPersonaName
0x016ae6e8  ascii  mMemberBlazeId
0x016ae748  ascii  mOwnersBlazeIds
0x016ae778  ascii  mBlazeObjId
0x016ae7e8  ascii  mOwnerBlazeId
0x016ae850  ascii  mMembersBlazeIds
0x016ae868  ascii  mBlazeUserId
0x016b0d10  ascii  Blaze::Authentication::AccountInfo
0x016b0dd0  ascii  Blaze::Authentication::UserProfileInfo
0x016b0e90  ascii  Blaze::Authentication::PersonaDetails
0x016b0fd0  ascii  Blaze::Authentication::UserDetails
0x016b1090  ascii  Blaze::Authentication::SessionInfo
0x016b1158  ascii  Blaze::Authentication::CreateAccountParameters
0x016b1228  ascii  Blaze::Authentication::FieldValidationError
0x016b1378  ascii  Blaze::Authentication::FieldValidateErrorList
0x016b1448  ascii  Blaze::Authentication::UpdateAccountRequest
0x016b1518  ascii  Blaze::Authentication::UpdateAccountResponse
0x016b15e8  ascii  Blaze::Authentication::ConsumecodeRequest
0x016b16b8  ascii  Blaze::Authentication::ConsumecodeResponse
0x016b1788  ascii  Blaze::Authentication::AcceptLegalDocsRequest
0x016b1860  ascii  Blaze::Authentication::GetEmailOptInSettingsRequest
0x016b1940  ascii  Blaze::Authentication::GetEmailOptInSettingsResponse
0x016b1a20  ascii  Blaze::Authentication::GetLegalDocContentRequest
0x016b1b00  ascii  Blaze::Authentication::GetLegalDocContentResponse
0x016b1bd8  ascii  Blaze::Authentication::OriginLoginRequest
0x016b1ca8  ascii  Blaze::Authentication::GetAuthTokenResponse
0x016b1d78  ascii  Blaze::Authentication::ExpressLoginRequest
0x016b1e48  ascii  Blaze::Authentication::FullLoginResponse
0x016b1f20  ascii  Blaze::Authentication::ConsoleCreateAccountRequest
0x016b1ff8  ascii  Blaze::Authentication::PasswordForgotRequest
0x016b20d0  ascii  Blaze::Authentication::GrantEntitlement2Request
0x016b2180  ascii  Blaze::Authentication::Entitlement
0x016b22c0  ascii  Blaze::Authentication::Entitlements
0x016b2390  ascii  Blaze::Authentication::ListUserEntitlements2Request
0x016b2468  ascii  Blaze::Authentication::PasswordRulesInfo
0x016b2540  ascii  Blaze::Authentication::GrantEntitlement2Response
0x016b26e0  ascii  Blaze::Association::ListMemberId
0x016b27a0  ascii  Blaze::Association::ListMemberInfo
0x016b2868  ascii  Blaze::Association::ListIdentification
0x016b2920  ascii  Blaze::Association::ListInfo
0x016b2a50  ascii  Blaze::Association::ListMembers
0x016b2b78  ascii  Blaze::Association::Lists
0x016b2cb8  ascii  Blaze::Association::UpdateListsRequest
0x016b2d80  ascii  Blaze::Association::UpdateListMembersRequest
0x016b2e50  ascii  Blaze::Association::UpdateListMembersResponse
0x016b2f10  ascii  Blaze::Association::GetListsRequest
0x016b32e0  ascii  Blaze::Authentication2::LoginRequest
0x016b3390  ascii  Blaze::Authentication2::PersonaDetails
0x016b3440  ascii  Blaze::Authentication2::SessionInfo
0x016b3500  ascii  Blaze::Authentication2::LoginResponse
0x016b3650  ascii  NotifyBlazeTwoWayCommunication
0x016b3670  ascii  Blaze::NFS::NotifyBlazeTwoWayCommunication
0x016b36a0  ascii  NotifyBlazeTwoWayCommunication::mInt32ParamList
0x016b36d0  ascii  NotifyBlazeTwoWayCommunication::mUint64ParamList
0x016b3708  ascii  NotifyBlazeTwoWayCommunication::mFloatParamList
0x016b3738  ascii  NotifyBlazeTwoWayCommunication::mStringParamList
0x016b82c0  ascii  mBlazeIdList
0x016b8300  ascii  mFriendBlazeId
0x016b8990  ascii  mBlazeIDs
0x016b8c18  ascii  mMeBlazeId
0x016b8d78  ascii  mContentAuthorBlazeId
0x016b8dd0  ascii  NEWS_PARAM_BLAZE_ID
0x016b8e28  ascii  mContentReporterBlazeId
0x016b9168  ascii  mBlazeIdToPlayedAgainstStatus
0x016b9330  ascii  mTargetBlazeUser
0x016ba098  ascii  mRivalBlazeUser
0x016ba3c0  ascii  mFriendBlazeIdList
0x016ba450  ascii  mRivalBlazeId
0x016ba730  ascii  mBlazeUser
0x016baaa8  ascii  mPlayerBlazeIdList
0x016bd1c0  ascii  BlazeUser
0x016bd1d0  ascii  Blaze::NFS::BlazeUser
0x016bd390  ascii  Blaze::NFS::GetSpecialGuestInfoResponse
0x016bd460  ascii  Blaze::NFS::GetSpecialGuestInfoRequest
0x016bd530  ascii  Blaze::NFS::SetSpecialGuestAttemptResponse
0x016bd600  ascii  Blaze::NFS::SetSpecialGuestAttemptRequest
0x016bd6d0  ascii  Blaze::NFS::SetGeolocationInfoRequest
0x016bd7a0  ascii  Blaze::NFS::SetGeolocationInfoResponse
0x016bd870  ascii  Blaze::NFS::SetGeoLocationOptOutRequest
0x016bd940  ascii  Blaze::NFS::SetGeoLocationOptOutResponse
0x016bda10  ascii  Blaze::NFS::GetGeolocationFromIPRequest
0x016bdae0  ascii  Blaze::NFS::GetGeolocationFromIPResponse
0x016bdbb0  ascii  Blaze::NFS::GetGeolocationInfoRequest
0x016bdc80  ascii  Blaze::NFS::GetGeolocationInfoResponse
0x016bddc8  ascii  Blaze::NFS::FriendsRecommendation
0x016bde90  ascii  Blaze::NFS::FriendsRecommendationsResponse
0x016bdf60  ascii  Blaze::NFS::FriendsRecommendationsRequest
0x016be038  ascii  Blaze::NFS::IngoreFriendRecommendationsRequest
0x016be118  ascii  Blaze::NFS::IngoreFriendRecommendationsResponse
0x016be238  ascii  Blaze::NFS::InGameSpeedWallsRequest
0x016be380  ascii  Blaze::NFS::InGameSpeedWallResponseRow
0x016be4d8  ascii  Blaze::NFS::InGameSpeedWallResponseSpeedWall
0x016be628  ascii  Blaze::NFS::InGameSpeedWallResponse
0x016be6f0  ascii  Blaze::NFS::InGameRecommendationsRequest
0x016be7d0  ascii  Blaze::NFS::InGameRecommendationsResponseRecommendation
0x016be930  ascii  Blaze::NFS::InGameRecommendationsRival
0x016beaa0  ascii  Blaze::NFS::InGameRecommendationsResponse
0x016beb78  ascii  Blaze::NFS::RecommendationRivalScoreResponse
0x016bec50  ascii  Blaze::NFS::RecommendationRivalScoreRequest
0x016bed10  ascii  Blaze::NFS::PlaylistRow
0x016bedc8  ascii  Blaze::NFS::GetPlaylistRequest
0x016bee88  ascii  Blaze::NFS::GetPlaylistResponse
0x016bef48  ascii  Blaze::NFS::SetPlaylistRequest
0x016bf008  ascii  Blaze::NFS::SetPlaylistResponse
0x016bf0d8  ascii  Blaze::NFS::SetOverwatchWeaponFeedbackRequest
0x016bf1b8  ascii  Blaze::NFS::SetOverwatchWeaponFeedbackResponse
0x016bf290  ascii  Blaze::NFS::IncrementOverwatchStatsRequest
0x016bf360  ascii  Blaze::NFS::IncrementOverwatchStatsResponse
0x016bf4b0  ascii  Blaze::NFS::ResetOverwatchStatsRequest
0x016bf580  ascii  Blaze::NFS::ResetOverwatchStatsResponse
0x016bf650  ascii  Blaze::NFS::GetOverwatchStatsConfigRequest
0x016bf720  ascii  Blaze::NFS::GetOverwatchStatsConfigResponse
0x016bf7f0  ascii  Blaze::NFS::SetInGameRichPresenceRequest
0x016bf8c0  ascii  Blaze::NFS::SetInGameRichPresenceResponse
0x016bf990  ascii  Blaze::NFS::RichPresenceWatchListRequest
0x016bfa60  ascii  Blaze::NFS::RichPresenceWatchListResponse
0x016bfb28  ascii  Blaze::NFS::ReportContentRequest
0x016bfbe8  ascii  Blaze::NFS::ReportContentResponse
0x016bfca8  ascii  SetSpecialGuestAttemptRequest::mBlazeIdToPlayedAgainstStatus
0x016bff70  ascii  mTargetBlazeId
0x016c01e8  ascii  RichPresenceWatchListRequest::mPlayerBlazeIdList
0x016c02d0  ascii  Blaze::NFS::InGameRealtimePresenceRequest
0x016c03a8  ascii  Blaze::NFS::InGameRealtimePresenceResponseData
0x016c0500  ascii  Blaze::NFS::InGameRealtimePresenceResponse
0x016c0600  ascii  InGameRealtimePresenceRequest::mFriendBlazeIdList
0x016c07e8  ascii  Blaze::ByteVault::AccessPermission
0x016c08a8  ascii  Blaze::ByteVault::CategorySettings
0x016c0950  ascii  Blaze::ByteVault::User
0x016c0a00  ascii  Blaze::ByteVault::RecordAddress
0x016c0ab0  ascii  Blaze::ByteVault::RecordInfo
0x016c0b60  ascii  Blaze::ByteVault::RecordPayload
0x016c0c08  ascii  Blaze::ByteVault::Record
0x016c0cd0  ascii  Blaze::ByteVault::AuthenticationCredentials
0x016c0e80  ascii  Blaze::ByteVault::AdminHistory
0x016c0f30  ascii  Blaze::ByteVault::CategoryHistory
0x016c0ff0  ascii  Blaze::ByteVault::ContextHistory
0x016c10b8  ascii  Blaze::ByteVault::JsonRecordPayload
0x016c1170  ascii  Blaze::ByteVault::JsonRecord
0x016c1228  ascii  Blaze::ByteVault::UpsertRecordRequest
0x016c12e8  ascii  Blaze::ByteVault::UpsertRecordResponse
0x016c13a8  ascii  Blaze::ByteVault::GetRecordRequest
0x016c1468  ascii  Blaze::ByteVault::GetRecordResponse
0x016c1528  ascii  Blaze::ByteVault::GetRecordInfoRequest
0x016c1668  ascii  Blaze::ByteVault::GetRecordInfoResponse
0x016c1728  ascii  Blaze::ByteVault::DeleteRecordRequest
0x016c1a90  ascii  Blaze::CensusData::RegionCounts
0x016c1b78  ascii  Blaze::Clubs::CustClubSettings
0x016c1c30  ascii  Blaze::Clubs::ClubSettings
0x016c1d60  ascii  Blaze::Clubs::ClubInfo
0x016c1e08  ascii  Blaze::Clubs::Club
0x016c1f30  ascii  Blaze::Clubs::ClubsCensusData
0x016c9cf0  ascii  Blaze::Redirector::ServerInstanceHttpRequest
0x016c9db0  ascii  Blaze::Rooms::RoomViewData
0x016c9e68  ascii  Blaze::Rooms::RoomCategoryData
0x016c9f20  ascii  Blaze::Rooms::RoomData
0x016c9fd0  ascii  Blaze::Rooms::RoomMemberData
0x016ca090  ascii  Blaze::Rooms::RoomViewReplicationContext
0x016ca160  ascii  Blaze::Rooms::RoomCategoryReplicationContext
0x016ca228  ascii  Blaze::Rooms::RoomReplicationContext
0x016ca2f0  ascii  Blaze::Rooms::RoomMemberReplicationContext
0x016ca580  ascii  Blaze::Util::ClientData
0x016ca640  ascii  Blaze::Util::FetchClientConfigRequest
0x016ca708  ascii  Blaze::Util::FetchConfigResponse
0x016ca7c0  ascii  Blaze::Util::UserText
0x016ca8f0  ascii  Blaze::Util::UserStringList
0x016ca9a0  ascii  Blaze::Util::PssConfig
0x016caa60  ascii  Blaze::Util::GetTelemetryServerResponse
0x016cab28  ascii  Blaze::Util::GetTickerServerResponse
0x016cabf0  ascii  Blaze::Util::GetTelemetryServerRequest
0x016cacb0  ascii  Blaze::Util::PingResponse
0x016cad60  ascii  Blaze::Util::PreAuthRequest
0x016cae60  ascii  Blaze::Util::PreAuthResponse
0x016caf10  ascii  Blaze::Util::UserOptions
0x016cafc0  ascii  Blaze::Util::PostAuthRequest
0x016cb078  ascii  Blaze::Util::PostAuthResponse
0x016cb138  ascii  Blaze::Util::UserSettingsResponse
0x016cb1f8  ascii  Blaze::Util::UserSettingsLoadRequest
0x016cb2b8  ascii  Blaze::Util::UserSettingsSaveRequest
0x016cb378  ascii  Blaze::Util::FilteredUserText
0x016cb4b8  ascii  Blaze::Util::FilterUserTextResponse
0x016cb7e0  ascii  Blaze::Stats::ScopeValues
0x016cb890  ascii  Blaze::Stats::KeyScopeItem
0x016cb9e0  ascii  Blaze::Stats::KeyScopes
0x016cba90  ascii  Blaze::Stats::StatDescSummary
0x016cbb40  ascii  Blaze::Stats::EntityStats
0x016cbbf8  ascii  Blaze::Stats::EntityStatAggregates
0x016cbdb0  ascii  Blaze::Stats::StatValues
0x016cbf08  ascii  Blaze::Stats::GetStatGroupRequest
0x016cc048  ascii  Blaze::Stats::StatGroupResponse
0x016cc108  ascii  Blaze::Stats::GetStatsByGroupRequest
0x016cc1c8  ascii  Blaze::Stats::LeaderboardGroupRequest
0x016cc330  ascii  Blaze::Stats::LeaderboardGroupResponse
0x016cc3f8  ascii  Blaze::Stats::LeaderboardStatsRequest
0x016cc5e0  ascii  Blaze::Stats::LeaderboardStatValuesRow
0x016cc728  ascii  Blaze::Stats::LeaderboardStatValues
0x016cc7f0  ascii  Blaze::Stats::CenteredLeaderboardStatsRequest
0x016cc8c0  ascii  Blaze::Stats::FilteredLeaderboardStatsRequest
0x016cc988  ascii  Blaze::Stats::KeyScopedStatValues
0x016cca48  ascii  Blaze::Stats::LeaderboardTreeNode
0x016cd330  ascii  AUTH2_ERR_UNKNOWN_BLAZE_ID
0x016ced18  ascii  mRequest.mBlazeSDKVersion
0x016ced40  ascii  mRequest.mBlazeSDKBuildDate
0x016d09b8  ascii  SDK_ERR_BLAZE_HUB_ALREADY_INITIALIZED
0x016d0ac0  ascii  SDK_ERR_BLAZE_CONN_TIMEOUT
0x016d0ae0  ascii  SDK_ERR_BLAZE_CONN_FAILED
0x016d9af8  ascii  mBlazeSDKVersion
0x016d9b68  ascii  mBlazeSDKBuildDate
0x016da950  ascii  BLAZESERVER_CONN_LOST
0x016dafb8  ascii  BLAZE_ID
0x016db0e0  ascii  mBlazeObjectIdList
0x016de550  ascii  Blaze::UserSessionDisconnectReason
0x016de618  ascii  Blaze::UserIdentification
0x016de6d0  ascii  Blaze::UserStatus
0x016de808  ascii  Blaze::LookupUsersRequest
0x016de8c0  ascii  Blaze::ClientInfo
0x016de978  ascii  Blaze::ResumeSessionRequest
0x016deab8  ascii  Blaze::UserManagerCensusData
0x016deb78  ascii  Blaze::UserSessionLoginInfo
0x016dec38  ascii  Blaze::UserSessionLogoutInfo
0x016dedd0  ascii  Blaze::UpdateHardwareFlagsRequest
0x016def68  ascii  Blaze::UserSessionExtendedData
0x016df010  ascii  Blaze::UserSessionExtendedDataUpdate
0x016df0d0  ascii  Blaze::NotifyUserAdded
0x016df188  ascii  Blaze::NotifyUserRemoved
0x016df258  ascii  Blaze::UpdateExtendedDataAttributeRequest
0x016df310  ascii  Blaze::UserData
0x016df438  ascii  Blaze::UserDataResponse
0x016df478  ascii  UserSessionExtendedData::mBlazeObjectIdList
0x016df588  ascii  Blaze::GameManager::CustomModRuleCriteria
0x016df660  ascii  Blaze::GameManager::MatchmakingCustomCriteriaData
0x016df740  ascii  Blaze::GameManager::MatchmakingCustomAsyncStatus
0x016df818  ascii  Blaze::GameManager::ReplicatedGamePlayer
0x016df8e0  ascii  Blaze::GameManager::HostInfo
0x016df990  ascii  Blaze::GameManager::RoleCriteria
0x016dfa50  ascii  Blaze::GameManager::RoleInformation
0x016dfb18  ascii  Blaze::GameManager::ReplicatedGameData
0x016dfbd8  ascii  Blaze::GameManager::CreateGameRequest
0x016dfca0  ascii  Blaze::GameManager::UpdateGameSessionRequest
0x016dfd78  ascii  Blaze::GameManager::UpdateGameHostMigrationStatusRequest
0x016dfe58  ascii  Blaze::GameManager::CreateGameResponse
0x016dff18  ascii  Blaze::GameManager::EjectHostRequest
0x016dffc0  ascii  Blaze::GameManager::DestroyGameRequest
0x016e0088  ascii  Blaze::GameManager::DestroyGameResponse
0x016e0140  ascii  Blaze::GameManager::JoinGameRequest
0x016e0208  ascii  Blaze::GameManager::JoinGameResponse
0x016e02d8  ascii  Blaze::GameManager::ResetDedicatedServerSetupContext
0x016e03a8  ascii  Blaze::GameManager::DatalessSetupContext
0x016e0480  ascii  Blaze::GameManager::IndirectJoinGameSetupContext
0x016e0558  ascii  Blaze::GameManager::MatchmakingSetupContext
0x016e0630  ascii  Blaze::GameManager::IndirectMatchmakingSetupContext
0x016e07b0  ascii  Blaze::GameManager::UpdateMeshConnectionRequest
0x016e0878  ascii  Blaze::GameManager::RemovePlayerRequest
0x016e0938  ascii  Blaze::GameManager::UpdateAdminListRequest
0x016e0a08  ascii  Blaze::GameManager::NotifyAdminListChange
0x016e0ad8  ascii  Blaze::GameManager::AdvanceGameStateRequest
0x016e0ba8  ascii  Blaze::GameManager::ReplayGameRequest
0x016e0c60  ascii  Blaze::GameManager::TeamMemberInfo
0x016e0da0  ascii  Blaze::GameManager::TeamDetails
0x016e0e58  ascii  Blaze::GameManager::SetPresenceModeRequest
0x016e0f28  ascii  Blaze::GameManager::SetGameSettingsRequest
0x016e1000  ascii  Blaze::GameManager::SetGameAttributesRequest
0x016e10d0  ascii  Blaze::GameManager::SetPlayerAttributesRequest
0x016e1210  ascii  Blaze::GameManager::NotifyGameSetup
0x016e12d8  ascii  Blaze::GameManager::NotifyPlayerJoining
0x016e13a0  ascii  Blaze::GameManager::NotifyPlayerJoinCompleted
0x016e1468  ascii  Blaze::GameManager::NotifyPlayerRemoved
0x016e1530  ascii  Blaze::GameManager::NotifyPlatformHostInitialized
0x016e1610  ascii  Blaze::GameManager::NotifyHostMigrationStart
0x016e16e0  ascii  Blaze::GameManager::NotifyHostMigrationFinished
0x016e17a8  ascii  Blaze::GameManager::NotifyGameAttribChange
0x016e1880  ascii  Blaze::GameManager::NotifyGameSettingsChange
0x016e1950  ascii  Blaze::GameManager::NotifyGameCapacityChange
0x016e1a20  ascii  Blaze::GameManager::NotifyPresenceModeChanged
0x016e1af0  ascii  Blaze::GameManager::NotifyPlayerAttribChange
0x016e1bc0  ascii  Blaze::GameManager::NotifyGameModRegisterChanged
0x016e1ca0  ascii  Blaze::GameManager::NotifyGameEntryCriteriaChanged
0x016e1d80  ascii  Blaze::GameManager::NotifyPlayerCustomDataChange
0x016e1e58  ascii  Blaze::GameManager::NotifyGameStateChange
0x016e1f20  ascii  Blaze::GameManager::NotifyGameReset
0x016e1ff0  ascii  Blaze::GameManager::NotifyGameReportingIdChange
0x016e20b8  ascii  Blaze::GameManager::NotifyGameRemoved
0x016e2180  ascii  Blaze::GameManager::NotifyGameRecreateRequested
0x016e2250  ascii  Blaze::GameManager::GameSessionUpdatedNotification
0x016e2330  ascii  Blaze::GameManager::NotifyGamePlayerStateChange
0x016e2408  ascii  Blaze::GameManager::NotifyGamePlayerTeamRoleSlotChange
0x016e24d8  ascii  Blaze::GameManager::NotifyGameTeamIdChange
0x016e25a8  ascii  Blaze::GameManager::NotifyProcessQueue
0x016e2668  ascii  Blaze::GameManager::NotifyGameNameChange
0x016e2738  ascii  Blaze::GameManager::NotifyQueueChanged
0x016e27f8  ascii  Blaze::GameManager::GameAttributeCensusData
0x016e2948  ascii  Blaze::GameManager::GameManagerCensusData
0x016e2a20  ascii  Blaze::GameManager::NumOfMatchmakingResponse
0x016e2af0  ascii  Blaze::GameManager::PreferredJoinOptOutRequest
0x016e2bc8  ascii  Blaze::GameManager::NotifyCreateDynamicDedicatedServerGame
0x016e2ca8  ascii  Blaze::GameManager::PingSiteRulePrefs
0x016e2d68  ascii  Blaze::GameManager::PingSiteRuleStatus
0x016e2e28  ascii  Blaze::GameManager::GenericRulePrefs
0x016e2ee8  ascii  Blaze::GameManager::GenericRuleStatus
0x016e2fa8  ascii  Blaze::GameManager::RankedGameRulePrefs
0x016e3060  ascii  Blaze::GameManager::RankRuleStatus
0x016e3128  ascii  Blaze::GameManager::TeamSizeRulePrefs
0x016e31e8  ascii  Blaze::GameManager::TeamSizeRuleStatus
0x016e32a8  ascii  Blaze::GameManager::GameSizeRulePrefs
0x016e3368  ascii  Blaze::GameManager::GameSizeRuleStatus
0x016e3428  ascii  Blaze::GameManager::RosterSizeRulePrefs
0x016e34e0  ascii  Blaze::GameManager::SkillRulePrefs
0x016e35a0  ascii  Blaze::GameManager::SkillRuleStatus
0x016e3660  ascii  Blaze::GameManager::DNFRulePrefs
0x016e3720  ascii  Blaze::GameManager::DNFRuleStatus
0x016e37e8  ascii  Blaze::GameManager::HostBalancingRulePrefs
0x016e38b8  ascii  Blaze::GameManager::HostBalanceRuleStatus
0x016e3988  ascii  Blaze::GameManager::HostViabilityRulePrefs
0x016e3a58  ascii  Blaze::GameManager::HostViabilityRuleStatus
0x016e3c28  ascii  Blaze::GameManager::MatchmakingCriteriaData
0x016e3cf0  ascii  Blaze::GameManager::FindGameStatus
0x016e3db8  ascii  Blaze::GameManager::CreateGameStatus
0x016e4058  ascii  Blaze::GameManager::MatchmakingAsyncStatus
0x016e41b0  ascii  Blaze::GameManager::NotifyMatchmakingAsyncStatus
0x016e4288  ascii  Blaze::GameManager::StartMatchmakingRequest
0x016e4360  ascii  Blaze::GameManager::StartMatchmakingResponse
0x016e4430  ascii  Blaze::GameManager::MatchmakingCriteriaError
0x016e4500  ascii  Blaze::GameManager::CancelMatchmakingRequest
0x016e45c8  ascii  Blaze::GameManager::NotifyMatchmakingFailed
0x016e4698  ascii  Blaze::GameManager::GameBrowserTeamInfo
0x016e4758  ascii  Blaze::GameManager::GameBrowserPlayerData
0x016e4928  ascii  Blaze::GameManager::GameBrowserGameData
0x016e49e8  ascii  Blaze::GameManager::GameBrowserMatchData
0x016e4b38  ascii  Blaze::GameManager::NotifyGameListUpdate
0x016eab28  ascii  EAO/Blaze/Unset
0x016eab38  ascii  EAO/Blaze/GameManager
0x016eab50  ascii  EAO/Blaze/PlayGroup
0x016efa38  ascii  Blaze::GameManager::GeoLocationRuleCriteria
0x016efb08  ascii  Blaze::GameManager::GeoLocationRuleStatus
0x016efbd8  ascii  Blaze::GameManager::GameNameRuleCriteria
0x016efca8  ascii  Blaze::GameManager::VirtualGameRulePrefs
0x016efd78  ascii  Blaze::GameManager::VirtualGameRuleStatus
0x016efe48  ascii  Blaze::GameManager::AvoidGamesRuleCriteria
0x016eff20  ascii  Blaze::GameManager::AvoidPlayersRuleCriteria
0x016efff0  ascii  Blaze::GameManager::PreferredPlayersRuleCriteria
0x016f00c0  ascii  Blaze::GameManager::UEDRuleCriteria
0x016f0180  ascii  Blaze::GameManager::UEDRuleStatus
0x016f0240  ascii  Blaze::GameManager::ModRuleCriteria
0x016f0308  ascii  Blaze::GameManager::PlayerCountRuleCriteria
0x016f03d8  ascii  Blaze::GameManager::PlayerCountRuleStatus
0x016f04b0  ascii  Blaze::GameManager::TotalPlayerSlotsRuleCriteria
0x016f0590  ascii  Blaze::GameManager::TotalPlayerSlotsRuleStatus
0x016f0660  ascii  Blaze::GameManager::FreePlayerSlotsRuleCriteria
0x016f0738  ascii  Blaze::GameManager::PlayerSlotUtilizationRuleCriteria
0x016f0810  ascii  Blaze::GameManager::PlayerSlotUtilizationRuleStatus
0x016f08e8  ascii  Blaze::GameManager::TeamBalanceRulePrefs
0x016f09b8  ascii  Blaze::GameManager::TeamBalanceRuleStatus
0x016f0a88  ascii  Blaze::GameManager::TeamMinSizeRulePrefs
0x016f0b58  ascii  Blaze::GameManager::TeamMinSizeRuleStatus
0x016f0c28  ascii  Blaze::GameManager::TeamCountRulePrefs
0x016f0ce8  ascii  Blaze::GameManager::ReputationRulePrefs
0x016f0e50  ascii  Blaze::GameReporting::ArsonClub::PlayerReport
0x016f0f10  ascii  Blaze::GameReporting::ArsonClub::ClubReport
0x016f1100  ascii  Blaze::GameReporting::ArsonClub::Report
0x016f11e0  ascii  Blaze::GameReporting::ArsonClubGameKeyscopes_NonDerived::ClubReport
0x016f12d0  ascii  Blaze::GameReporting::ArsonClubGameKeyscopes_NonDerived::OffensiveAthlete
0x016f13a0  ascii  Blaze::GameReporting::ArsonClubGameKeyscopes_NonDerived::PlayerReport
0x016f1650  ascii  Blaze::GameReporting::ArsonClubGameKeyscopes_NonDerived::Report
0x016f1740  ascii  Blaze::GameReporting::ArsonCTF_NonDerived::PlayerReport
0x016f1818  ascii  Blaze::GameReporting::ArsonCTF_NonDerived::SkippedPlayerReport
0x016f18f0  ascii  Blaze::GameReporting::ArsonCTF_NonDerived::GameAttributes
0x016f1a50  ascii  Blaze::GameReporting::ArsonCTF_NonDerived::Report
0x016f1b10  ascii  Blaze::GameReporting::ArsonCTF_Common::PlayerReport
0x016f1bd0  ascii  Blaze::GameReporting::ArsonCTF_Common::GameAttributes
0x016f1d30  ascii  Blaze::GameReporting::ArsonCTF_Common::Report
0x016f1de0  ascii  Blaze::GameReporting::ArsonCTF_Derived::PlayerReport
0x016f1ec0  ascii  Blaze::GameReporting::ArsonCTF_Custom::PlayerReport
0x016f1f80  ascii  Blaze::GameReporting::ArsonCTF_Custom::GameAttributes
0x016f20e0  ascii  Blaze::GameReporting::ArsonCTF_Custom::Report
0x016f2190  ascii  Blaze::GameReporting::ArsonCTF_Custom::ResultNotification
0x016f22a0  ascii  Blaze::GameReporting::ArsonCTF_EndGame::PlayerReport
0x016f2360  ascii  Blaze::GameReporting::ArsonCTF_EndGame::GameAttributes
0x016f24c0  ascii  Blaze::GameReporting::ArsonCTF_EndGame::Report
0x016f2570  ascii  Blaze::GameReporting::ArsonCTF_GSA_NonDerived::PlayerReport
0x016f2630  ascii  Blaze::GameReporting::ArsonCTF_GSA_NonDerived::GameAttributes
0x016f2790  ascii  Blaze::GameReporting::ArsonCTF_GSA_NonDerived::Report
0x016f2850  ascii  Blaze::GameReporting::ArsonCTF_GSA_Common::PlayerReport
0x016f2910  ascii  Blaze::GameReporting::ArsonCTF_GSA_Common::GameAttributes
0x016f2a70  ascii  Blaze::GameReporting::ArsonCTF_GSA_Common::Report
0x016f2b30  ascii  Blaze::GameReporting::ArsonCTF_GSA_Derived::PlayerReport
0x016f2bf0  ascii  Blaze::GameReporting::ArsonCTF_KS_NonDerived::PlayerReport
0x016f2cb0  ascii  Blaze::GameReporting::ArsonCTF_KS_NonDerived::GameAttributes
0x016f2e10  ascii  Blaze::GameReporting::ArsonCTF_KS_NonDerived::Report
0x016f2ed0  ascii  Blaze::GameReporting::ArsonCTF_KS_Common::PlayerReport
0x016f2f90  ascii  Blaze::GameReporting::ArsonCTF_KS_Common::GameAttributes
0x016f30f0  ascii  Blaze::GameReporting::ArsonCTF_KS_Common::Report
0x016f31b0  ascii  Blaze::GameReporting::ArsonCTF_KS_Derived::PlayerReport
0x016f3270  ascii  Blaze::GameReporting::ArsonCTF_MidGame::PlayerReport
0x016f3330  ascii  Blaze::GameReporting::ArsonCTF_MidGame::GameAttributes
0x016f3490  ascii  Blaze::GameReporting::ArsonCTF_MidGame::Report
0x016f3540  ascii  Blaze::GameReporting::GameHistoryBasic::PlayerReport
0x016f3600  ascii  Blaze::GameReporting::GameHistoryBasic::GameAttributes
0x016f3760  ascii  Blaze::GameReporting::GameHistoryBasic::Report
0x016f3810  ascii  Blaze::GameReporting::GameHistoryClubs_NonDerived::OffensiveAthlete
0x016f38e0  ascii  Blaze::GameReporting::GameHistoryClubs_NonDerived::PlayerReport
0x016f39a0  ascii  Blaze::GameReporting::GameHistoryClubs_NonDerived::ClubReport
0x016f3c40  ascii  Blaze::GameReporting::GameHistoryClubs_NonDerived::Report
0x016f7948  ascii  mJoiningBlazeIds
0x016f9780  ascii  Blaze::Messaging::ServerMessage
0x016f9838  ascii  Blaze::Messaging::SendMessageResponse
0x016f99e0  ascii  Blaze::Playgroups::PlaygroupInfo
0x016f9aa8  ascii  Blaze::Playgroups::PlaygroupMemberInfo
0x016f9b70  ascii  Blaze::Playgroups::UpdatePlaygroupSessionRequest
0x016f9c48  ascii  Blaze::Playgroups::NotifyDestroyPlaygroup
0x016f9d98  ascii  Blaze::Playgroups::NotifyJoinPlaygroup
0x016f9e60  ascii  Blaze::Playgroups::NotifyMemberJoinedPlaygroup
0x016f9f30  ascii  Blaze::Playgroups::NotifyMemberRemoveFromPlaygroup
0x016fa008  ascii  Blaze::Playgroups::NotifyLeaderChange
0x016fa0d0  ascii  Blaze::Playgroups::NotifyMemberPermissionsChange
0x016fa1b0  ascii  Blaze::Playgroups::NotifyPlaygroupAttributesSet
0x016fa280  ascii  Blaze::Playgroups::NotifyMemberAttributesSet
0x016fa350  ascii  Blaze::Playgroups::NotifyJoinControlsChange
0x016fa418  ascii  Blaze::Playgroups::NotifyXboxSessionInfo
0x016fa4e8  ascii  Blaze::Playgroups::PlaygroupCensusData
0x016fa580  ascii  NotifyJoinPlaygroup::mJoiningBlazeIds
0x016fa610  ascii  NotifyMemberRemoveFromPlaygroup::mBlazeIds
0x016fa730  ascii  Blaze::Redirector::IpAddress
0x016fa7d0  ascii  Blaze::Redirector::XboxServerAddress
0x016fa928  ascii  Blaze::Redirector::AddressRemapEntry
0x016fa9e0  ascii  Blaze::Redirector::NameRemapEntry
0x016faaa8  ascii  Blaze::Redirector::ServerAddressInfo
0x016fabe8  ascii  Blaze::Redirector::ServerEndpointInfo
0x016fad20  ascii  Blaze::Redirector::ServerInstance
0x016faf60  ascii  Blaze::Redirector::ServerInfoData
0x016fb018  ascii  Blaze::Redirector::XboxId
0x016fb178  ascii  Blaze::Redirector::ServerInstanceRequest
0x016fb298  ascii  Blaze::Redirector::ServerInstanceInfo
0x016fb358  ascii  Blaze::Redirector::ServerInstanceError
0x016fcfa8  ascii  mBlazeError
0x016fdac0  ascii  Blaze::GameReporting::GameReport
0x016fdb88  ascii  Blaze::GameReporting::SubmitGameReportRequest
0x016fdc40  ascii  Blaze::GameReporting::ResultNotification
0x016fdcf0  ascii  Blaze::GameReporting::SampleBase::PlayerReport
0x016fdda0  ascii  Blaze::GameReporting::SampleBase::GameAttributes
0x016fdf00  ascii  Blaze::GameReporting::SampleBase::Report
0x016fe040  ascii  Blaze::GameReporting::Shooter::EntityReport
0x016fe1a0  ascii  Blaze::GameReporting::Shooter::GroupReport
0x016fe390  ascii  Blaze::GameReporting::Shooter::Report
0x01700600  ascii  Blaze::GameReporting::ArsonLeague::PlayerReport
0x017006b0  ascii  Blaze::GameReporting::ArsonLeague::GameAttributes
0x01700780  ascii  Blaze::GameReporting::ArsonLeague::OffensiveStats
0x01700850  ascii  Blaze::GameReporting::ArsonLeague::DefensiveStats
0x01700920  ascii  Blaze::GameReporting::ArsonLeague::AthleteReport
0x01700b20  ascii  Blaze::GameReporting::ArsonLeague::Report
0x01700bf0  ascii  Blaze::GameReporting::ArsonLeagueGameKeyscopes::GameAttributes
0x01700cb0  ascii  Blaze::GameReporting::ArsonLeagueGameKeyscopes::PlayerReport
0x01700d70  ascii  Blaze::GameReporting::ArsonLeagueGameKeyscopes::OffensiveAthlete
0x01700e60  ascii  Blaze::GameReporting::ArsonLeagueGameKeyscopes::DefensiveAthlete
0x01701110  ascii  Blaze::GameReporting::ArsonLeagueGameKeyscopes::Report
0x017011f0  ascii  Blaze::GameReporting::ArsonMultiKeyscopes::Weapon
0x01701350  ascii  Blaze::GameReporting::ArsonMultiKeyscopes::PlayerReport
0x01701410  ascii  Blaze::GameReporting::ArsonMultiKeyscopes::GameAttributes
0x01701570  ascii  Blaze::GameReporting::ArsonMultiKeyscopes::Report
0x01701640  ascii  Blaze::GameReporting::ArsonMultiStatUpdates::GameAttributes
0x01701700  ascii  Blaze::GameReporting::ArsonMultiStatUpdates::PlayerReport
0x017017c0  ascii  Blaze::GameReporting::ArsonMultiStatUpdates::OffensiveAthlete
0x017019c0  ascii  Blaze::GameReporting::ArsonMultiStatUpdates::Report
0x01701a80  ascii  Blaze::GameReporting::ArsonMultiStatUpdatesKeyscopes::GameAttributes
0x01701b50  ascii  Blaze::GameReporting::ArsonMultiStatUpdatesKeyscopes::PlayerReport
0x01701c20  ascii  Blaze::GameReporting::ArsonMultiStatUpdatesKeyscopes::OffensiveAthlete
0x01701e30  ascii  Blaze::GameReporting::ArsonMultiStatUpdatesKeyscopes::Report
0x01701ef0  ascii  Blaze::GameReporting::Frostbite::EntityReport
0x01702040  ascii  Blaze::GameReporting::Frostbite::GroupReport
0x01702190  ascii  Blaze::GameReporting::Frostbite::Report
0x01702258  ascii  Blaze::GameReporting::Frostbite::ResultNotificationData
0x01702360  ascii  Blaze::GameReporting::Ghost::PlayerReport
0x01702410  ascii  Blaze::GameReporting::Ghost::Report
0x01702500  ascii  Blaze::GameReporting::IntegratedSample::PlayerReport
0x017025c0  ascii  Blaze::GameReporting::IntegratedSample::GameAttributes
0x01702720  ascii  Blaze::GameReporting::IntegratedSample::Report
0x017027d8  ascii  Blaze::GameReporting::NFS::Bounty::Bounty
0x01702890  ascii  Blaze::GameReporting::NFS::Bounty::Report
0x01703b38  ascii  BlazeObjectType
0x01703b48  ascii  BlazeObjectId
0x01704428  ascii  X-BLAZE-METHOD
0x017058b0  ascii  mBlazeFlags
0x01705af8  ascii  mBlazeObjectId
0x01705be0  ascii  mBlazeObjectType
0x01706360  ascii  Blaze::DynamicInetFilter::CidrBlock
0x01706410  ascii  Blaze::DynamicInetFilter::Entry
0x017064e0  ascii  Blaze::DynamicInetFilter::ReplicatedInetFilterReplicationReason
0x017065b8  ascii  Blaze::EntryCriteriaError
0x01706660  ascii  Blaze::IpAddress
0x01706710  ascii  Blaze::HostNameAddress
0x017067c0  ascii  Blaze::IpPairAddress
0x01706878  ascii  Blaze::XboxClientAddress
0x01706920  ascii  Blaze::XboxServerAddress
0x01706ab0  ascii  Blaze::Util::NetworkQosData
0x01706b60  ascii  Blaze::QosPingSiteInfo
0x01706c10  ascii  Blaze::QosConfigInfo
0x01706d30  ascii  Blaze::NetworkInfo
0x01706de0  ascii  Blaze::ClientMetrics
```

## dirtysdk (11)

_DirtySDK - EA's network layer. The ProtoSSL version decides whether the client accepts our server's stand-in certificate._

```
0x016534f8  ascii  NetConnection
0x016cee48  ascii  mRequest.mDirtySDKVersion
0x016d0880  ascii  SDK_ERR_DIRTYSOCK_UNINITIALIZED
0x016da758  ascii  mPlayerNetConnectionFlags
0x016da990  ascii  mPlayerNetConnectionStatus
0x016deca8  ascii  mDirtySDKVersion
0x0170c8a8  ascii  User-Agent: ProtoHttp %d.%d/DS %d.%d.%d.%d.%d (Windows)
0x0170d1a0  ascii  protossl session
0x0170d318  ascii  netgamelink
0x0170e3b8  ascii  commudp-global
0x0170eda0  ascii  protoadvt
```

## components (535)

_Blaze component and command names - the map of RPCs we have to handle._

```
0x00df174b  ascii  xUtIL2
0x01424c70  ascii  ClientMetricsUIActionMessage
0x01424d60  ascii  ClientMetricsPauseGameMessage
0x01426388  ascii  ClientMetricsPushUIScreenMessage
0x01426460  ascii  ClientMetricsPopUIScreenMessage
0x014616d0  ascii  TinyEvent_AckAuthentication
0x014616f0  ascii  TinyEvent_NackAuthentication
0x0147bc38  ascii  EntityInteractionUtils isEntityOccluded
0x01489868  ascii  LeaderboardName
0x01489898  ascii  AbstractLeaderboardData
0x0148a570  ascii  DeltaGameReports
0x015413e8  ascii  UtilConfigValueEntity
0x015417f8  ascii  LeaderboardComparePBEntity
0x01541d58  ascii  LeaderboardMapRefEntity
0x01541d98  ascii  T_LEADERBOARDS
0x01541e48  ascii  LeaderboardCompareTopSpeedwallEntity
0x01549370  ascii  ClientTelemetryEntity
0x0154a628  ascii  MatchmakingSettings
0x0154a640  ascii  SessionMatchmakingSettings
0x0154abb0  ascii  telemetry_isproduction
0x0154abd0  ascii  telemetry_block_
0x01572360  ascii  ClientEventStartAreaLeaderboardHelperEntity
0x0158d260  ascii  ClientLeaderboardEntity
0x0158df20  ascii  ClientJumpLeaderboardRowEntity
0x0158df40  ascii  ClientLeaderboardRowEntity
0x0158dff0  ascii  ClientLeaderboardReferenceEntity
0x015a0338  ascii  ClientUISpeedlistLeaderboardDataProviderEntity
0x015a0368  ascii  ClientUILeaderboardDataProviderEntity
0x015a05b8  ascii  ClientUIEventLeaderboardDataProviderEntity
0x015a9528  ascii  ClientUIResultsLeaderboardMessageCollectorEntity
0x015a95e8  ascii  ClientUIResultsLeaderboardMessageCollectorProxyEntity
0x015b74d0  ascii  ClientUISelectedCollectibleLeaderboardDecoratorPointOfInterestProviderEntity
0x015b75e0  ascii  ClientUISelectedEventLeaderboardDecoratorPointOfInterestProviderEntity
0x015c6c48  ascii  LeaderboardId
0x015cb760  ascii  WaitForAssociationLists
0x015cb778  ascii  Matchmaking
0x015cb7f8  ascii  Matchmake
0x015cb818  ascii  matchmaking_retries
0x015cd5c0  ascii  UIShowResultsLeaderboardMessage
0x015cd620  ascii  LeaderboardTypeName
0x015cd648  ascii  LeaderboardTypeIconString
0x015cd6e0  ascii  LeaderboarDownloadOffset
0x015cd728  ascii  LeaderboardMinDistance
0x015cd768  ascii  LeaderboardMaxDistance
0x015cd7a0  ascii  LeaderboardMinDrawDistance
0x015cd7e0  ascii  LeaderboardMaxDrawDistance
0x015cd800  ascii  LeaderboardMaxSpeed
0x015d0e10  ascii  LeaderboardCompareTopSpeedwallEntityData
0x015d0e70  ascii  LeaderboardDownloadEnabled
0x015d0e90  ascii  LeaderboardDownloadRange
0x015d0eb0  ascii  EventStartAreaLeaderboardHelperEntityData
0x015d0f00  ascii  UtilConfigValueEntityData
0x015d0f20  ascii  LeaderboardMapRefEntityData
0x015d1398  ascii  LeaderboardComparePBEntityData
0x015d22a0  ascii  UISelectedEventLeaderboardDecoratorPointOfInterestProviderEntityData
0x015d2520  ascii  UISelectedCollectibleLeaderboardDecoratorPointOfInterestProviderEntityData
0x015d6fd0  ascii  MatchmakingDirtyCast
0x015d6fe8  ascii  StartMatchmake
0x015d6ff8  ascii  MatchmakeSuccess
0x015d7010  ascii  MatchmakeFailed
0x015d7020  ascii  MatchmakeStop
0x015d7070  ascii  matchmakingSkill_Rule
0x015dbfe0  ascii  UISpeedlistLeaderboardDataProviderEntityData
0x015dc338  ascii  UIEventLeaderboardDataProviderEntityData
0x015dc3d0  ascii  UILeaderboardDataProviderEntityData
0x015dd620  ascii  TelemetryOptIn
0x015de8a8  ascii  UIResultsLeaderboardMessageCollectorEntityData
0x015de938  ascii  UIResultsLeaderboardMessageCollectorProxyEntityData
0x015ef158  ascii  RaceJuiceSendTelemetryEventMessage
0x015f88a0  ascii  LeaderboardEntityData
0x015f8958  ascii  TelemetryParamDataType_Integer
0x015f8978  ascii  TelemetryParamDataType_Float
0x015f8998  ascii  TelemetryParamDataType_String
0x015f89d0  ascii  TelemetryParamDataType_UnsignedInteger
0x015f89f8  ascii  TelemetryParamDataType
0x015f8c18  ascii  LeaderboardReferenceEntityData
0x015f8cd0  ascii  JumpLeaderboardRowEntityData
0x015f8e50  ascii  LeaderboardRowEntityData
0x015f8eb8  ascii  LeaderboardContentType_Friends
0x015f8ed8  ascii  LeaderboardContentType_Global
0x015f8ef8  ascii  LeaderboardContentType
0x015f8f10  ascii  LeaderboardSortOrder_Ascending
0x015f8f30  ascii  LeaderboardSortOrder_Descending
0x015f8f50  ascii  MatchmakingMode
0x015f8f60  ascii  LeaderboardSortOrder
0x015f8f78  ascii  MatchmakingSkill
0x015f9010  ascii  TelemetryParamDataProperty
0x015f9120  ascii  TelemetryEntityData
0x015f9138  ascii  LeaderboardAsset
0x016836c8  ascii  Reflection\Util\hkVariantDataUtil.cpp
0x0168c088  ascii  Util\hkStructureLayout.cpp
0x01690888  ascii  Util\Welding\hkpMeshWeldingUtility.cpp
0x01691468  ascii  hkpWeldingUtility
0x01691480  ascii  !hkpWeldingUtility
0x016915b8  ascii  Util\ShapeShrinker\hkpShapeShrinker.cpp
0x01696098  ascii  util
0x01696120  ascii  limitContactImpulseUtilAndFlag
0x0169dd60  ascii  Collide\ShapeUtils\ShapeConverter\hkpShapeConverter.cpp
0x0169ede0  ascii  utils\hkRagdollUtils.cpp
0x0169f1e8  ascii  Misc\hkGeometryUtils.cpp
0x016a0970  ascii  Utility
0x016a0978  ascii  GameManager
0x016a66f8  ascii  ORIGIN_ERROR_CORE_AUTHENTICATION_FAILED
0x016a6720  ascii  Origin Core seems to be running, but the LSX Authentication Challenge failed. No communication with Core is possible.
0x016a7590  ascii  UTILITY
0x016ad988  ascii  mAuthenticationSource
0x016b0b00  ascii  MatchmakingSession::MatchmakingCreateGameParameters.mGameAttributeMap
0x016b0b50  ascii  MatchmakingSession::MatchmakingCreateGameParameters.mEntryCriteriaMap
0x016b0ba0  ascii  MatchmakingSession::MatchmakingSessionParameters.mPlayerAttributeMap
0x016b0be8  ascii  MatchmakingSession::MatchmakingSessionParameters.mPlayerRoles
0x016b0c30  ascii  MatchmakingSession::MatchmakingSessionParameters.mExternalPlayerRoles
0x016b8958  ascii  mLeaderboard
0x016b89e0  ascii  mOnlineLeaderboard
0x016b97a0  ascii  mCensusDataList
0x016c0cb0  ascii  AuthenticationCredentials
0x016c1f20  ascii  ClubsCensusData
0x016c2208  ascii  ClubsCensusData::mNumOfClubMembersByDomain
0x016c2238  ascii  ClubsCensusData::mNumOfOnlineClubMembersByDomain
0x016c2270  ascii  ClubsCensusData::mNumOfClubsByDomain
0x016c2298  ascii  ClubsCensusData::mNumOfOnlineClubsByDomain
0x016c6740  ascii  mLeaderboardSize
0x016c6ab8  ascii  TELEMETRY_OPT_OUT
0x016c6ae8  ascii  TELEMETRY_OPT_IN
0x016c6c10  ascii  mTelemetryOpt
0x016c6d58  ascii  mTelemetryServer
0x016c7030  ascii  mEnableDisconnectTelemetry
0x016c7670  ascii  mUserSessionId
0x016c7770  ascii  mTelemetryServiceName
0x016caa40  ascii  GetTelemetryServerResponse
0x016cabd0  ascii  GetTelemetryServerRequest
0x016cad50  ascii  PreAuthRequest
0x016cae50  ascii  PreAuthResponse
0x016cafb0  ascii  PostAuthRequest
0x016cb060  ascii  PostAuthResponse
0x016cc1b0  ascii  LeaderboardGroupRequest
0x016cc310  ascii  LeaderboardGroupResponse
0x016cc3e0  ascii  LeaderboardStatsRequest
0x016cc5c0  ascii  LeaderboardStatValuesRow
0x016cc710  ascii  LeaderboardStatValues
0x016cc7d0  ascii  CenteredLeaderboardStatsRequest
0x016cc8a0  ascii  FilteredLeaderboardStatsRequest
0x016cca30  ascii  LeaderboardTreeNode
0x016ccc90  ascii  LeaderboardGroupResponse::mStatKeyColumns
0x016cccc0  ascii  LeaderboardGroupResponse::mKeyScopeNameValueListMap
0x016cccf8  ascii  LeaderboardStatsRequest::mKeyScopeNameValueMap
0x016ccd58  ascii  LeaderboardStatValuesRow::mOtherStats
0x016ccd80  ascii  LeaderboardStatValuesRow::mOtherRawStats
0x016ccdb0  ascii  LeaderboardStatValues::mRows
0x016ccdd0  ascii  CenteredLeaderboardStatsRequest::mKeyScopeNameValueMap
0x016cce08  ascii  FilteredLeaderboardStatsRequest::mListOfIds
0x016cce38  ascii  FilteredLeaderboardStatsRequest::mKeyScopeNameValueMap
0x016ccec8  ascii  PreAuthResponse::mComponentIds
0x016ccf70  ascii  AssociationListsComponent
0x016cd050  ascii  ASSOCIATIONLIST_ERR_USER_NOT_FOUND
0x016cd078  ascii  ASSOCIATIONLIST_ERR_DUPLICATE_USER_FOUND
0x016cd0a8  ascii  ASSOCIATIONLIST_ERR_CANNOT_INCLUDE_SELF
0x016cd0d0  ascii  ASSOCIATIONLIST_ERR_INVALID_USER
0x016cd0f8  ascii  ASSOCIATIONLIST_ERR_MEMBER_ALREADY_IN_THE_LIST
0x016cd128  ascii  ASSOCIATIONLIST_ERR_MEMBER_NOT_FOUND_IN_THE_LIST
0x016cd160  ascii  ASSOCIATIONLIST_ERR_LIST_NOT_FOUND
0x016cd188  ascii  ASSOCIATIONLIST_ERR_LIST_IS_FULL_OR_TOO_MANY_USERS
0x016cd1c0  ascii  ASSOCIATIONLIST_ERR_PAIRED_LIST_MODIFICATION_NOT_SUPPORTED
0x016cd200  ascii  ASSOCIATIONLIST_ERR_PAIRED_LIST_IS_FULL_OR_TOO_MANY_USERS
0x016cd240  ascii  ASSOCIATIONLIST_ERR_SUBSCRIBE_USER_LIST_NOT_SUPPORTED
0x016cd2d8  ascii  Authentication2Component
0x016cd3e8  ascii  AuthenticationComponent
0x016cd440  ascii  createWalUserSession
0x016cec88  ascii  redirector/getServerInstance
0x016cf2e8  ascii  RedirectorComponent
0x016cf358  ascii  REDIRECTOR_SERVER_NOT_FOUND
0x016cf378  ascii  REDIRECTOR_NO_SERVER_CAPACITY
0x016cf398  ascii  REDIRECTOR_NO_MATCHING_INSTANCE
0x016cf3b8  ascii  REDIRECTOR_SERVER_NAME_ALREADY_IN_USE
0x016cf3e0  ascii  REDIRECTOR_CLIENT_NOT_COMPATIBLE
0x016cf408  ascii  REDIRECTOR_CLIENT_UNKNOWN
0x016cf428  ascii  REDIRECTOR_UNKNOWN_CONNECTION_PROFILE
0x016cf450  ascii  REDIRECTOR_SERVER_SUNSET
0x016cf470  ascii  REDIRECTOR_SERVER_DOWN
0x016cf488  ascii  REDIRECTOR_INVALID_PARAMETER
0x016cf4a8  ascii  REDIRECTOR_UNKNOWN_SERVICE_NAME
0x016cf4c8  ascii  REDIRECTOR_PAST_EVENT
0x016cf4e0  ascii  REDIRECTOR_UNKNOWN_SCHEDULE_ID
0x016cf500  ascii  REDIRECTOR_MISSING_SERVICE_NAME
0x016cf558  ascii  RedirectorProxyComponent
0x016cf590  ascii  UserSessionExtendedDataUpdate
0x016cf610  ascii  getCenteredLeaderboard
0x016cf628  ascii  getCenteredLeaderboardRaw
0x016cf678  ascii  getFilteredLeaderboard
0x016cf690  ascii  getFilteredLeaderboardRaw
0x016cf6c0  ascii  getLeaderboard
0x016cf6d0  ascii  getLeaderboardEntityCount
0x016cf6f0  ascii  getLeaderboardFolderGroup
0x016cf710  ascii  getLeaderboardGroup
0x016cf728  ascii  getLeaderboardRaw
0x016cf740  ascii  getLeaderboardTreeAsync
0x016cf810  ascii  STATS_ERR_INVALID_LEADERBOARD_ID
0x016cfa78  ascii  STATS_ERR_LEADERBOARD_NOT_IN_MEMORY
0x016cfaa0  ascii  GetLeaderboardTreeNotification
0x016cfb18  ascii  UserSessionsComponent
0x016cfc08  ascii  lookupUserSessionId
0x016cfcf8  ascii  updateUserSessionClientData
0x016d0010  ascii  UserSessionDisconnected
0x016d0088  ascii  UtilComponent
0x016d0100  ascii  getTelemetryServer
0x016d0150  ascii  postAuth
0x016d0160  ascii  preAuth
0x016d0178  ascii  setClientMetrics
0x016d0220  ascii  UTIL_CONFIG_NOT_FOUND
0x016d0238  ascii  UTIL_PSS_NO_SERVERS_AVAILABLE
0x016d0258  ascii  UTIL_TELEMETRY_NO_SERVERS_AVAILABLE
0x016d0280  ascii  UTIL_TELEMETRY_OUT_OF_MEMORY
0x016d02a0  ascii  UTIL_TELEMETRY_KEY_TOO_LONG
0x016d02c0  ascii  UTIL_TELEMETRY_INVALID_MAC_ADDRESS
0x016d02e8  ascii  UTIL_TICKER_NO_SERVERS_AVAILABLE
0x016d0310  ascii  UTIL_TICKER_KEY_TOO_LONG
0x016d0330  ascii  UTIL_USS_RECORD_NOT_FOUND
0x016d0350  ascii  UTIL_USS_TOO_MANY_KEYS
0x016d0368  ascii  UTIL_USS_DB_ERROR
0x016d0380  ascii  UTIL_USS_USER_NO_EXTENDED_DATA
0x016d03a0  ascii  UTIL_SUSPEND_PING_TIME_TOO_LARGE
0x016d03c8  ascii  UTIL_SUSPEND_PING_TIME_TOO_SMALL
0x016d0478  ascii  ERR_AUTHENTICATION_REQUIRED
0x016d3910  ascii  GameManagerAPI::mUserToGameToJobMap
0x016d3938  ascii  GameManagerAPI::mGameMap
0x016d3958  ascii  GameManagerAPI::mMatchmakingSessionList
0x016d3980  ascii  GameManagerAPI::mGameBrowserListMap
0x016d39a8  ascii  GameManagerAPI::mUserSetGameListMap
0x016d39e0  ascii  GMAPI::MatchmakingPool
0x016d3a28  ascii  GameManagerAPI::GameToJobMap
0x016d4930  ascii  TelemetryAPIArray
0x016d5df0  ascii  MessagingAPIArray
0x016d5e08  ascii  MessagingAPI::mDispatcherByTypeMap
0x016d5e30  ascii  MessagingAPI::mDispatcherByComponentMap
0x016d5f68  ascii  PlaygroupAPI::mPlaygroupList
0x016d5f88  ascii  PlaygroupAPI::mUserToGameToJobMap
0x016d5fb0  ascii  PGAPI::PlaygroupPool
0x016d5fc8  ascii  PlaygroupAPI::PlaygroupToJobMap
0x016d90e8  ascii  mUsersessionidList
0x016d9338  ascii  mPlayerSlotUtilizationRuleStatus
0x016d9a08  ascii  mMatchmakingResult
0x016d9ab8  ascii  mPlayerSlotUtilizationRuleCriteria
0x016d9b80  ascii  mMatchmakingAsyncStatusList
0x016d9c28  ascii  mMatchmakingSessionId
0x016da190  ascii  JOIN_BY_MATCHMAKING
0x016da6e0  ascii  mGameReportingId
0x016dab30  ascii  GM_NUM_PLAYER_IN_MATCHMAKING
0x016dab98  ascii  EXTERNAL_SESSION_PLAYGROUP
0x016dabb8  ascii  EXTERNAL_SESSION_MATCHMAKINGSESSION
0x016db1a0  ascii  mNumOfMatchmakingSession
0x016db270  ascii  mNumOfMatchmakingSessions
0x016de530  ascii  UserSessionDisconnectReason
0x016deaa0  ascii  UserManagerCensusData
0x016deb60  ascii  UserSessionLoginInfo
0x016dec20  ascii  UserSessionLogoutInfo
0x016dece0  ascii  UserManagerCensusData::mConnectedPlayerCounts
0x016ded10  ascii  mUserSessionType
0x016def50  ascii  UserSessionExtendedData
0x016df450  ascii  UserSessionExtendedData::mDataMap
0x016df4a8  ascii  UserSessionExtendedData::mLatencyList
0x016df640  ascii  MatchmakingCustomCriteriaData
0x016df720  ascii  MatchmakingCustomAsyncStatus
0x016e0540  ascii  MatchmakingSetupContext
0x016e0610  ascii  IndirectMatchmakingSetupContext
0x016e1fd0  ascii  NotifyGameReportingIdChange
0x016e27e0  ascii  GameAttributeCensusData
0x016e2930  ascii  GameManagerCensusData
0x016e2a00  ascii  NumOfMatchmakingResponse
0x016e3c10  ascii  MatchmakingCriteriaData
0x016e4040  ascii  MatchmakingAsyncStatus
0x016e4190  ascii  NotifyMatchmakingAsyncStatus
0x016e4270  ascii  StartMatchmakingRequest
0x016e4340  ascii  StartMatchmakingResponse
0x016e4410  ascii  MatchmakingCriteriaError
0x016e44e0  ascii  CancelMatchmakingRequest
0x016e45b0  ascii  NotifyMatchmakingFailed
0x016e5588  ascii  mMatchmakingSetupContext
0x016e55a8  ascii  mIndirectMatchmakingSetupContext
0x016e5828  ascii  GameManagerCensusData::mGameAttributesData
0x016e58f8  ascii  MatchmakingCriteriaData::mSkillRulePrefsList
0x016e5928  ascii  MatchmakingCriteriaData::mGenericRulePrefsList
0x016e5958  ascii  MatchmakingCriteriaData::mUEDRuleCriteriaMap
0x016e5988  ascii  MatchmakingCriteriaData::mVariableCustomRulePrefs
0x016e59c0  ascii  MatchmakingAsyncStatus::mSkillRuleStatusMap
0x016e59f0  ascii  MatchmakingAsyncStatus::mGenericRuleStatusMap
0x016e5a20  ascii  MatchmakingAsyncStatus::mUEDRuleStatusMap
0x016e5a50  ascii  MatchmakingAsyncStatus::mVariableCustomAsyncStatus
0x016e5a88  ascii  NotifyMatchmakingAsyncStatus::mMatchmakingAsyncStatusList
0x016e5ac8  ascii  StartMatchmakingRequest::mGameAttribs
0x016e5af0  ascii  StartMatchmakingRequest::mRoleJoinRoster
0x016e5b20  ascii  StartMatchmakingRequest::mExternalPlayerRoleJoinRoster
0x016e5b58  ascii  StartMatchmakingRequest::mPlayerAttribs
0x016e5b80  ascii  StartMatchmakingRequest::mEntryCriteriaMap
0x016e5bb0  ascii  StartMatchmakingRequest::mPlayerIdList
0x016e5bd8  ascii  StartMatchmakingRequest::mReservedExternalPlayers
0x016e7f60  ascii  AUTOLOG_ERR_SPEEDWALL_STATS_LEADERBOARD_FAILED
0x016e7f90  ascii  AUTOLOG_ERR_SPEEDWALL_STATS_LEADERBOARD_GROUP_FAILED
0x016e7fc8  ascii  AUTOLOG_ERR_SPEEDWALL_STATS_LEADERBOARD_LIST_FAILED
0x016e8000  ascii  AUTOLOG_ERR_SPEEDWALL_GET_FILTERED_LEADERBOARD_FAILED
0x016e8490  ascii  BYTEVAULT_AUTHENTICATION_REQUIRED
0x016e85d8  ascii  GameManagerComponent
0x016e8640  ascii  cancelMatchmaking
0x016e8770  ascii  getMatchmakingConfig
0x016e8990  ascii  startMatchmaking
0x016e8a40  ascii  GAMEMANAGER_ERR_INVALID_GAME_SETTINGS
0x016e8a68  ascii  GAMEMANAGER_ERR_INVALID_GAME_ID
0x016e8a88  ascii  GAMEMANAGER_ERR_JOIN_METHOD_NOT_SUPPORTED
0x016e8ab8  ascii  GAMEMANAGER_ERR_GAME_FULL
0x016e8ad8  ascii  GAMEMANAGER_ERR_INVALID_GAME_STATE_TRANSITION
0x016e8b08  ascii  GAMEMANAGER_ERR_INVALID_GAME_STATE_ACTION
0x016e8b38  ascii  GAMEMANAGER_ERR_FAILED_IN_GAME_DESTROY
0x016e8b60  ascii  GAMEMANAGER_ERR_QUEUE_FULL
0x016e8b80  ascii  GAMEMANAGER_ERR_INVALID_GAME_ENTRY_CRITERIA
0x016e8bb0  ascii  GAMEMANAGER_ERR_GAME_PROTOCOL_VERSION_MISMATCH
0x016e8be0  ascii  GAMEMANAGER_ERR_GAME_IN_PROGRESS
0x016e8c08  ascii  GAMEMANAGER_ERR_RESERVED_GAME_ID_INVALID
0x016e8c38  ascii  GAMEMANAGER_ERR_INVALID_JOIN_METHOD
0x016e8c60  ascii  GAMEMANAGER_ERR_SLOT_OCCUPIED
0x016e8c80  ascii  GAMEMANAGER_ERR_NOT_VIRTUAL_GAME
0x016e8ca8  ascii  GAMEMANAGER_ERR_NOT_TOPOLOGY_HOST
0x016e8cd0  ascii  GAMEMANAGER_ERR_PERMISSION_DENIED
0x016e8cf8  ascii  GAMEMANAGER_ERR_ALREADY_ADMIN
0x016e8d18  ascii  GAMEMANAGER_ERR_NOT_IN_ADMIN_LIST
0x016e8d40  ascii  GAMEMANAGER_ERR_DEDICATED_SERVER_HOST
0x016e8d68  ascii  GAMEMANAGER_ERR_INVALID_QUEUE_METHOD
0x016e8d90  ascii  GAMEMANAGER_ERR_PLAYER_NOT_IN_QUEUE
0x016e8db8  ascii  GAMEMANAGER_ERR_DEQUEUE_WHILE_MIGRATING
0x016e8de0  ascii  GAMEMANAGER_ERR_DEQUEUE_WHILE_IN_PROGRESS
0x016e8e10  ascii  GAMEMANAGER_ERR_PLAYER_NOT_FOUND
0x016e8e38  ascii  GAMEMANAGER_ERR_ALREADY_GAME_MEMBER
0x016e8e60  ascii  GAMEMANAGER_ERR_REMOVE_PLAYER_FAILED
0x016e8e88  ascii  GAMEMANAGER_ERR_INVALID_PLAYER_PASSEDIN
0x016e8eb0  ascii  GAMEMANAGER_ERR_JOIN_PLAYER_FAILED
0x016e8ed8  ascii  GAMEMANAGER_ERR_PLAYER_BANNED
0x016e8ef8  ascii  GAMEMANAGER_ERR_GAME_ENTRY_CRITERIA_FAILED
0x016e8f28  ascii  GAMEMANAGER_ERR_ALREADY_IN_QUEUE
0x016e8f50  ascii  GAMEMANAGER_ERR_ENFORCING_SINGLE_GROUP_JOINS
0x016e8f80  ascii  GAMEMANAGER_ERR_BANNED_PLAYER_NOT_FOUND
0x016e8fa8  ascii  GAMEMANAGER_ERR_BANNED_LIST_MAX
0x016e8fc8  ascii  GAMEMANAGER_ERR_XSESSION_ID_MISMATCH
0x016e8ff0  ascii  GAMEMANAGER_ERR_FAILED_REPUTATION_CHECK
0x016e9018  ascii  GAMEMANAGER_ERR_RESERVATION_ALREADY_EXISTS
0x016e9048  ascii  GAMEMANAGER_ERR_NO_RESERVATION_FOUND
0x016e9070  ascii  GAMEMANAGER_ERR_INVALID_GAME_ENTRY_TYPE
0x016e9098  ascii  GAMEMANAGER_ERR_INVALID_GROUP_ID
0x016e90c0  ascii  GAMEMANAGER_ERR_PLAYER_NOT_IN_GROUP
0x016e90e8  ascii  GAMEMANAGER_ERR_INVALID_MATCHMAKING_CRITERIA
0x016e9118  ascii  GAMEMANAGER_ERR_UNKNOWN_MATCHMAKING_SESSION_ID
0x016e9148  ascii  GAMEMANAGER_ERR_NOT_MATCHMAKING_SESSION_OWNER
0x016e9178  ascii  GAMEMANAGER_ERR_MATCHMAKING_NO_JOINABLE_GAMES
0x016e91a8  ascii  GAMEMANAGER_ERR_MATCHMAKING_USERSESSION_NOT_FOUND
0x016e91e0  ascii  GAMEMANAGER_ERR_MATCHMAKING_EXCEEDED_MAX_REQUESTS
0x016e9218  ascii  GAMEMANAGER_ERR_PLAYER_CAPACITY_TOO_SMALL
0x016e9248  ascii  GAMEMANAGER_ERR_PLAYER_CAPACITY_TOO_LARGE
0x016e9278  ascii  GAMEMANAGER_ERR_PLAYER_CAPACITY_IS_ZERO
0x016e92a0  ascii  GAMEMANAGER_ERR_MAX_PLAYER_CAPACITY_TOO_LARGE
0x016e92d0  ascii  GAMEMANAGER_ERR_INVALID_TEAM_CAPACITIES_VECTOR_SIZE
0x016e9308  ascii  GAMEMANAGER_ERR_DUPLICATE_TEAM_CAPACITY
0x016e9330  ascii  GAMEMANAGER_ERR_INVALID_TEAM_ID_IN_TEAM_CAPACITIES_VECTOR
0x016e9370  ascii  GAMEMANAGER_ERR_TEAM_NOT_ALLOWED
0x016e9398  ascii  GAMEMANAGER_ERR_TOTAL_TEAM_CAPACITY_INVALID
0x016e93c8  ascii  GAMEMANAGER_ERR_TEAM_FULL
0x016e93e8  ascii  GAMEMANAGER_ERR_TEAMS_DISABLED
0x016e9408  ascii  GAMEMANAGER_ERR_PLAYER_CAPACITY_NOT_EVENLY_DIVISIBLE_BY_TEAMS
0x016e9448  ascii  GAMEMANAGER_ERR_EMPTY_ROLE_CAPACITIES
0x016e9470  ascii  GAMEMANAGER_ERR_ROLE_CAPACITY_TOO_SMALL
0x016e9498  ascii  GAMEMANAGER_ERR_ROLE_CAPACITY_TOO_LARGE
0x016e94c0  ascii  GAMEMANAGER_ERR_ROLE_NOT_ALLOWED
0x016e94e8  ascii  GAMEMANAGER_ERR_ROLE_FULL
0x016e9508  ascii  GAMEMANAGER_ERR_ROLE_CRITERIA_INVALID
0x016e9530  ascii  GAMEMANAGER_ERR_ROLE_CRITERIA_FAILED
0x016e9558  ascii  GAMEMANAGER_ERR_MULTI_ROLE_CRITERIA_INVALID
0x016e9588  ascii  GAMEMANAGER_ERR_NO_DEDICATED_SERVER_FOUND
0x016e95b8  ascii  GAMEMANAGER_ERR_DEDICATED_SERVER_ONLY_ACTION
0x016e95e8  ascii  GAMEMANAGER_ERR_DEDICATED_SERVER_HOST_CANNOT_JOIN
0x016e9648  ascii  GAMEMANAGER_ERR_DYNAMIC_GAME_CREATION_TIMED_OUT
0x016e9678  ascii  GAMEMANAGER_ERR_DYNAMIC_GAME_CREATION_FAILED_NO_CAPACITY
0x016e96b8  ascii  GAMEMANAGER_ERR_DYNAMIC_DEDICATED_SERVER_MODE_CONFLICT
0x016e96f0  ascii  GAMEMANAGER_ERR_NO_HOSTS_AVAILABLE_FOR_INJECTION
0x016e9860  ascii  GAMEMANAGER_ERR_GAME_CAPACITY_TOO_SMALL
0x016e9888  ascii  GAMEMANAGER_ERR_INVALID_ACTION_FOR_GROUP
0x016e98b8  ascii  GAMEMANAGER_ERR_NOT_PLATFORM_HOST
0x016e98e0  ascii  GAMEMANAGER_ERR_MIGRATION_NOT_SUPPORTED
0x016e9908  ascii  GAMEMANAGER_ERR_INVALID_NEWHOST
0x016e9928  ascii  GAMEMANAGER_ERR_USER_NOT_IN_ANY_GAME
0x016e9950  ascii  GAMEMANAGER_ERR_INVALID_PERSISTED_GAME_ID_OR_SECRET
0x016e9988  ascii  GAMEMANAGER_ERR_PERSISTED_GAME_ID_IN_USE
0x016e9ab0  ascii  GameReportingComponent
0x016e9ac8  ascii  getGameReportColumnInfo
0x016e9ae0  ascii  getGameReportColumnValues
0x016e9b00  ascii  getGameReportQueriesList
0x016e9b20  ascii  getGameReportQuery
0x016e9b38  ascii  getGameReports
0x016e9b48  ascii  getGameReportTypes
0x016e9b60  ascii  getGameReportView
0x016e9b78  ascii  getGameReportViewInfo
0x016e9b90  ascii  getGameReportViewInfoList
0x016e9bc8  ascii  submitGameReport
0x016e9be0  ascii  submitOfflineGameReport
0x016e9bf8  ascii  submitTrustedEndGameReport
0x016e9c18  ascii  submitTrustedMidGameReport
0x016e9c48  ascii  GAMEREPORTING_ERR_UNEXPECTED_REPORT
0x016e9c70  ascii  GAMEREPORTING_COLLATION_ERR_NO_VALID_REPORTS
0x016e9ca0  ascii  GAMEREPORTING_COLLATION_ERR_NO_REPORTS
0x016e9cc8  ascii  GAMEREPORTING_COLLATION_REPORTS_INCONSISTENT
0x016e9cf8  ascii  GAMEREPORTING_COLLATION_ERR_MISSING_GAME_ATTRIBUTE
0x016e9d30  ascii  GAMEREPORTING_COLLATION_ERR_INVALID_GAME_ATTRIBUTE
0x016e9d68  ascii  GAMEREPORTING_CUSTOM_ERR_PROCESSING_FAILED
0x016e9d98  ascii  GAMEREPORTING_CONFIG_ERR_MISSING_PROCESSOR_ATTRIBUTE
0x016e9dd0  ascii  GAMEREPORTING_CONFIG_ERR_INVALID_PROCESSOR_ATTRIBUTE
0x016e9e08  ascii  GAMEREPORTING_CONFIG_ERR_STAT_UPDATE_FAILED
0x016e9e38  ascii  GAMEREPORTING_CUSTOM_ERR_PROCESS_UPDATED_STATS_FAILED
0x016e9e70  ascii  GAMEREPORTING_ERR_INVALID_GAME_TYPE
0x016e9e98  ascii  GAMEREPORTING_OFFLINE_ERR_INVALID_GAME_TYPE
0x016e9ec8  ascii  GAMEREPORTING_OFFLINE_ERR_REPORT_INVALID
0x016e9ef8  ascii  GAMEREPORTING_TRUSTED_ERR_INVALID_GAME_TYPE
0x016e9f28  ascii  GAMEREPORTING_TRUSTED_ERR_REPORT_INVALID
0x016e9f58  ascii  GAMEREPORTING_TRUSTED_ERR_CLIENT_NOT_TRUSTED
0x016ea7a8  ascii  AssociationListMemberVector
0x016ea7c8  ascii  associationListSkipInitialSet
0x016ea800  ascii  AssociationListAPIAssociationListList
0x016ea828  ascii  ALAPI::AssociationListPool
0x016eb498  ascii  LeaderboardTreeFolder::mLeaderboardList
0x016eb4c0  ascii  LeaderboardTreeFolder::mFolderList
0x016eb4e8  ascii  Leaderboard:mViewList
0x016eb500  ascii  LeaderboardAPI::mLBFolderTable
0x016eb520  ascii  LeaderboardAPI::mLBFolderNameTable
0x016eb548  ascii  LeaderboardAPI::mLeaderboardTreeMap
0x016eb570  ascii  LeaderboardView::mScopeNameValueMap
0x016eb598  ascii  FilteredLeaderboardView::mEntityIdList
0x016f0710  ascii  PlayerSlotUtilizationRuleCriteria
0x016f07f0  ascii  PlayerSlotUtilizationRuleStatus
0x016f7290  ascii  mPlaygroupIdList
0x016f7320  ascii  mPlaygroupInfoList
0x016f7358  ascii  PLAYGROUP_MEMBER_REMOVE_REASON_DEFAULT
0x016f7390  ascii  PLAYGROUP_MEMBER_REMOVE_REASON_DISCONNECTED
0x016f73c0  ascii  PLAYGROUP_MEMBER_REMOVE_REASON_KICKED
0x016f73f8  ascii  PLAYGROUP_MEMBER_REMOVE_TITLE_BASE_REASON
0x016f7438  ascii  PLAYGROUP_DESTROY_REASON_DEFAULT
0x016f7460  ascii  PLAYGROUP_DESTROY_REASON_DISCONNECTED
0x016f7488  ascii  PLAYGROUP_DESTROY_REASON_LEADER_CHANGE_DISABLED
0x016f74e0  ascii  PLAYGROUP_DESTROY_REASON_LOCAL_PLAYERS_LEAVING
0x016f7528  ascii  PLAYGROUP_OPEN
0x016f7538  ascii  PLAYGROUP_CLOSED
0x016f7560  ascii  mPlaygroupKey
0x016f75d0  ascii  PG_NUM_OF_PLAYGROUPS
0x016f7620  ascii  mPlaygroupAttributes
0x016f7680  ascii  mTargetUserSessionIds
0x016f7740  ascii  mNumOfPlaygroup
0x016f7770  ascii  mNumOfPlayersInPlaygroup
0x016f78f8  ascii  mPlaygroupMemberInfoList
0x016f7b38  ascii  mPlaygroupJoinability
0x016f7b68  ascii  mPlaygroupId
0x016f7e70  ascii  mLeaderboardType
0x016f7f88  ascii  mLeaderboardSummaries
0x016f7fb0  ascii  mLeaderboardView
0x016f8530  ascii  mPlaygroupInfo
0x016f99d0  ascii  PlaygroupInfo
0x016f9a90  ascii  PlaygroupMemberInfo
0x016f9b50  ascii  UpdatePlaygroupSessionRequest
0x016f9c30  ascii  NotifyDestroyPlaygroup
0x016f9d80  ascii  NotifyJoinPlaygroup
0x016f9e40  ascii  NotifyMemberJoinedPlaygroup
0x016f9f10  ascii  NotifyMemberRemoveFromPlaygroup
0x016fa190  ascii  NotifyPlaygroupAttributesSet
0x016fa4d0  ascii  PlaygroupCensusData
0x016fa510  ascii  PlaygroupInfo::mPlaygroupAttributes
0x016fa558  ascii  PlaygroupMemberInfo::mMemberAttributes
0x016fa5a8  ascii  NotifyJoinPlaygroup::mPlaygroupMemberInfoList
0x016fa5d8  ascii  NotifyMemberJoinedPlaygroup::mPlaygroupMemberInfoList
0x016fa640  ascii  NotifyPlaygroupAttributesSet::mPlaygroupAttributes
0x016fcb38  ascii  mGameReportTypes
0x016fcbb0  ascii  mMaxGameReport
0x016fcc48  ascii  mGameReportQuery
0x016fcc98  ascii  mGameReportList
0x016fcce8  ascii  GAMEREPORT_FINISHED_STATUS_DEFAULT
0x016fcd20  ascii  GAMEREPORT_FINISHED_STATUS_FINISHED
0x016fcd48  ascii  GAMEREPORT_FINISHED_STATUS_DNF
0x016fdab0  ascii  GameReport
0x016fdb70  ascii  SubmitGameReportRequest
0x016fe468  ascii  GameReport::mOfflineParticipantList
0x016fe4a0  ascii  mGameReport
0x017058c0  ascii  mProductAssociationList
0x01706dd0  ascii  ClientMetrics
0x01709a80  ascii  MessagingComponent
0x01709b00  ascii  MESSAGING_ERR_UNKNOWN
0x01709b18  ascii  MESSAGING_ERR_MAX_ATTR_EXCEEDED
0x01709b38  ascii  MESSAGING_ERR_DATABASE
0x01709b50  ascii  MESSAGING_ERR_TARGET_NOT_FOUND
0x01709b70  ascii  MESSAGING_ERR_TARGET_TYPE_INVALID
0x01709b98  ascii  MESSAGING_ERR_TARGET_INBOX_FULL
0x01709bb8  ascii  MESSAGING_ERR_MATCH_NOT_FOUND
0x01709bd8  ascii  MESSAGING_ERR_FEATURE_DISABLED
0x01709bf8  ascii  MESSAGING_ERR_INVALID_PARAM
0x01709c60  ascii  PlaygroupsComponent
0x01709c78  ascii  createPlaygroup
0x01709c88  ascii  destroyPlaygroup
0x01709ca0  ascii  finalizePlaygroupCreation
0x01709cc0  ascii  joinPlaygroup
0x01709cd0  ascii  kickPlaygroupMember
0x01709ce8  ascii  leavePlaygroup
0x01709cf8  ascii  lookupPlaygroupInfo
0x01709d10  ascii  resetPlaygroupSession
0x01709d28  ascii  setPlaygroupAttributes
0x01709d40  ascii  setPlaygroupJoinControls
0x01709d60  ascii  PLAYGROUPS_ERR_NOT_IN_GROUP
0x01709d80  ascii  PLAYGROUPS_ERR_NOT_AUTHORIZED
0x01709da0  ascii  PLAYGROUPS_ERR_GROUP_FULL
0x01709dc0  ascii  PLAYGROUPS_ERR_INVALID_ENTITY
0x01709de0  ascii  PLAYGROUPS_ERR_GROUP_NOT_FOUND
0x01709e00  ascii  PLAYGROUPS_ERR_GROUP_CLOSED
0x01709e20  ascii  PLAYGROUPS_ERR_USER_NOT_IN_ANY_GROUP
0x01709e48  ascii  PLAYGROUPS_ERR_GROUP_ALREADY_EXISTS
0x01709e70  ascii  PLAYGROUPS_ERR_ALREADY_IN_GROUP
0x01709e90  ascii  PLAYGROUPS_ERR_INVALID_CREATE_CRITERIA
0x01709eb8  ascii  PLAYGROUPS_ERR_USER_NOT_IN_USER_GROUP
0x01709ee0  ascii  PLAYGROUPS_ERR_MEMBER_CAPACITY_TOO_SMALL
0x01709f10  ascii  NotifyMemberRemovedFromPlaygroup
0x0170eaf0  ascii  GmUtil
0x01715702  ascii   The ReverbIR1 PlugIn supports the use of two impulse responses at the same time. This allows for efficient cross fading from one environment to another, or the blending of two environments to create a third. This is immensely more efficient than using two separate ReverbIR voice instances, as the extra amount of memory and cycles required to support two reverbs rather than one within the PlugIn is very small. To utilize this feature, users must simply specify the reverb number (APPLYREVERBPARAM_REVERBNUMBER) along with the impulse response file (APPLYREVERBPARAM_REVERBFILE) when applying the reverb with the apply reverb event (EVENT_APPLYREVERB). In addition, to set the relative level of each reverb file the associated gain attribute should be set (i.e., ATTRIBUTE_REVERB0GAIN for reverb 0). Users must also ensure that any impulse response files being simultaneously used have the same number of channels, samples per block, and high frequency cut values.
0x0171d3d0  ascii  The BandPassFir64 PlugIn is a high quality linear phase bandpass filter with excellent isolation. The filter provides zero dB gain in the pass band, and a minimum of 50 dB stop band attenuation with a very narrow transition bandwidth in between.The filter uses only feed-forward elements, and as such can be classified as a Finite Impulse Response (FIR) filter. The filter is of order 64, utilizing 64 delay elements, and possessing the same number of zeros in its transfer function. Given its FIR nature, the phase response of the filter is linear, and the filter is unconditionally stable.
0x0173b320  ascii  The HighPassFir64 PlugIn is a high quality linear phase highpass filter with excellent isolation. The filter provides zero dB gain in the pass band, and a minimum of 50 dB stop band attenuation with a very narrow transition bandwidth in between.The filter uses only feed-forward elements, and as such can be classified as a Finite Impulse Response (FIR) filter. The filter is of order 64, utilizing 64 delay elements, and possessing the same number of zeros in its transfer function. Given its FIR nature, the phase response of the filter is linear, and the filter is unconditionally stable.
0x01747220  ascii  The LowPassFir64 PlugIn is a high quality linear phase lowpass filter with excellent isolation. The filter provides zero dB gain in the pass band, and a minimum of 50 dB stop band attenuation with a very narrow transition bandwidth in between.The filter uses only feed-forward elements, and as such can be classified as a Finite Impulse Response (FIR) filter. The filter is of order 64, utilizing 64 delay elements, and possessing the same number of zeros in its transfer function. Given its FIR nature, the phase response of the filter is linear, and the filter is unconditionally stable.
0x01759741  ascii  If, however, there is little or no correlation between some or all of the channels of a given multi-channel source, use of the MULTICHANNELMODE_COMBINED_CHANNELS mode can result in a poor quality stretched or contracted signal. In that case, the MULTICHANNELMODE_INDEPENDENT_CHANNELS mode should be used, so that each channel is analyzed and processed separately. This mode will produce a processing load that is proportional to the number of channels present, so that for example, stretching a stereo source will utilize about the same number of cycles as stretching two separate mono sources. If not explicitly specified, the time stretcher defaults to this mode of operation.
0x0175ae82  ascii  On the PS3 (post EAAudioCore 5.02.01), a special initialization is required before any UserMusicArbiter instances are created. Game code must call UserMusicArbiter::GetEAAudioCoreCellSysutilCallback() to obtain the UserMusicArbiter's CellSysutilCallback() function pointer, which takes the same parameter as the Sony CellSysutilCallback() version. This returned function should then be called from the game's registered CellSysutilCallback() handler in order for UserMusicArbiter to regularly determine BGM playback status and work properly.
0x0175b0a8  ascii  CellSysutilCallback sEaacCellSysutilCallbackFn = 0;
0x0175b0dc  ascii  void CellSysutilCallbackHandler(uint64_t status, uint64_t param, void *userdata)
0x0175b144  ascii  case CELL_SYSUTIL_REQUEST_EXITGAME:
0x0175b174  ascii  case CELL_SYSUTIL_SYSTEM_MENU_OPEN:
0x0175b1a4  ascii  case CELL_SYSUTIL_SYSTEM_MENU_CLOSE:
0x0175b1e1  ascii  // Call UserMusicArbiter's CellSysutilCallback function
0x0175b21c  ascii  sEaacCellSysutilCallbackFn(status, param, userdata);
0x0175b270  ascii  sEaacCellSysutilCallbackFn = EA::Audio::Core::UserMusicArbiter::GetEAAudioCoreCellSysutilCallback();
0x0175b2d6  ascii  cellSysutilRegisterCallback(0, CellSysutilCallbackHandler, 0);
0x0175b34d  ascii  // ... Periodically checks PS3 events by calling cellSysutilCheckCallback()
0x0177d530  ascii  hkRegisterCheckUtil
```

## auth (206)

_Login layer - how the client gets a token from the EA App and what it does with it._

```
0x014078f4  ascii  Origin
0x01491cd8  ascii  EntitlementType_Ignored
0x01491d28  ascii  EntitlementType_Write
0x01491d68  ascii  EntitlementType_Read
0x01491e38  ascii  EntitlementType
0x014923f0  ascii  STPersonal
0x01492a98  ascii  EntitlementTag
0x01492f58  ascii  EntitlementData
0x014932a8  ascii  EntitlementsData
0x014938a8  ascii  EntitlementQuery
0x01515378  ascii  PersonalityIndex
0x01515390  ascii  PersonalityProxyEntityData
0x01530a20  ascii  PersonalityProxyEntity
0x015482c0  ascii  Entitlement
0x01548ad0  ascii  personaLookupList
0x01548c78  ascii  %AUTHTOKEN%
0x01551d30  ascii  ClientEntitlementEntity
0x01551df0  ascii  ClientEntitlementLibraryEntity
0x01551e80  ascii  ClientEntitlementActivatorEntity
0x01553850  ascii  EntitlementLibrary
0x01595378  ascii  CreatePersonaEntity
0x015cbd10  ascii  ID_SIGNIN_ERROR_INVALID_PERSONA
0x015cbd30  ascii  ID_SIGNIN_ERROR_PERSONA_TOO_SHORT
0x015cbd58  ascii  ID_SIGNIN_ERROR_PERSONA_ALREADY_EXISTS
0x015d75e0  ascii  persona_name
0x015dd340  ascii  Persona
0x015dd348  ascii  CreatePersonaEntityData
0x015e63a0  ascii  PersonalityName
0x015e6418  ascii  PersonalityLibraryEntityData
0x015e64a0  ascii  PersonalityEntityData
0x015e67c8  ascii  PersonaName
0x015e6830  ascii  PersonaEntityData
0x015e6918  ascii  VehiclePersonaLinkEntityData
0x015e6cf0  ascii  PersonaLibraryEntityData
0x015e7bf8  ascii  BotPersonality
0x015ed496  ascii  I@PersonaLibraryEntity
0x015ed4b0  ascii  PersonalityLibraryEntity
0x015ed4d0  ascii  PersonaEntity
0x015ed4e0  ascii  PersonalityEntity
0x015f9328  ascii  NucleusBaseUri
0x015f9338  ascii  NucleusBaseProxyUri
0x015f9350  ascii  NucleusWaitingUri
0x015f9368  ascii  NucleusRedirectUri
0x015f9380  ascii  NucleusScope
0x015f93d0  ascii  EntitlementQueries
0x015fa080  ascii  VehicleWeaponEntitlement
0x015fa110  ascii  VehicleEntitlements
0x015fa140  ascii  EntitlementLibraryEntityData
0x015fa240  ascii  VehicleEntitlement
0x015fa258  ascii  EntitlementActivatorEntityData
0x015fa278  ascii  EntitlementEntityData
0x015fa548  ascii  VehicleLiveryEntitlement
0x015fac78  ascii  VehicleLiveryEntitlements
0x015fac98  ascii  VehicleWeaponEntitlements
0x016032c8  ascii  PersonalBestScore
0x0169fce0  ascii  OriginQueryEntitlements entered
0x0169fd00  ascii  OriginConsumeEntitlement entered
0x0169fda0  ascii  %s(%d) Origin Error: 0x%08X; Last OS Error: 0x%08x; %s
0x016a0888  ascii  AuthToken
0x016a53d8  ascii  QueryEntitlementsResponse
0x016a53f8  ascii  ConsumeEntitlementResponse
0x016a60f0  ascii  ORIGIN_ERROR_INVALID_PERSONA
0x016a6110  ascii  The specified persona is not valid in this context, or the personaId is invalid.
0x016a6190  ascii  The Origin SDK was not running.
0x016a6250  ascii  The Origin SDK is running. This operation should only be done before the SDK is initialized or after the SDK is shutdown.
0x016a6508  ascii  The Origin SDK is already initialized.
0x016a6558  ascii  The Origin SDK is still running.
0x016a6670  ascii  The Origin desktop application is not loaded.
0x016a66c0  ascii  Core couldn't authenticate with the Origin Servers.
0x016a6908  ascii  The Origin installation couldn't be found.
0x016a85e8  ascii  GetAuthToken
0x016a8668  ascii  QueryEntitlements
0x016a8680  ascii  ConsumeEntitlement
0x016a86c8  ascii  PersonaId
0x016a8a48  ascii  EntitlementId
0x016a8b50  ascii  :Entitlement
0x016a8d18  utf16  SOFTWARE\Wow6432Node\Origin
0x016ad6b0  ascii  mPersonaId
0x016adb38  ascii  NO_SUCH_PERSONA
0x016adc78  ascii  NO_SUCH_PERSONA_REFERENCE
0x016adcd0  ascii  mNucleusId
0x016adf18  ascii  mWithPersona
0x016adf60  ascii  NO_SUCH_ENTITLEMENT
0x016adf78  ascii  PERSONA
0x016adf80  ascii  mEntitlements
0x016adfb0  ascii  NUCLEUS_USER
0x016adfd8  ascii  NUCLEUS_PERSONA
0x016ae1d8  ascii  mEntitlementTag
0x016ae270  ascii  mEntitlementSearchFlag
0x016ae2d8  ascii  mAuthToken
0x016ae2e8  ascii  mEntitlementInfo
0x016ae358  ascii  mPCLoginToken
0x016ae470  ascii  mPersonaInfo
0x016ae488  ascii  USER_OR_PERSONA
0x016ae528  ascii  mIsBindPersona
0x016ae548  ascii  mPersonaName
0x016ae5d0  ascii  mHasAuthorizedPersona
0x016ae798  ascii  mPersonaDetailsList
0x016ae878  ascii  mEntitlementId
0x016ae8b8  ascii  AUTHTOKEN
0x016ae8c8  ascii  PCLOGINTOKEN
0x016ae900  ascii  mAccessToken
0x016ae930  ascii  mSessionKey
0x016aea40  ascii  mPersonaDetails
0x016aeb30  ascii  mEmailOrOriginPersona
0x016b0e80  ascii  PersonaDetails
0x016b1c90  ascii  GetAuthTokenResponse
0x016b20b0  ascii  GrantEntitlement2Request
0x016b22b0  ascii  Entitlements
0x016b2370  ascii  ListUserEntitlements2Request
0x016b2520  ascii  GrantEntitlement2Response
0x016b3120  ascii  UserDetails::mPersonaDetailsList
0x016b31a0  ascii  mEntitlementType
0x016b31e0  ascii  Entitlements::mEntitlements
0x016b3200  ascii  ListUserEntitlements2Request::mGroupNameList
0x016b97c0  ascii  mPersona
0x016b98b0  ascii  NUCLEUS_AUTH_TOKEN
0x016b98e8  ascii  NUCLEUS_ACCESS_TOKEN
0x016c20f0  ascii  mReceiverPersona
0x016c2118  ascii  mSenderPersona
0x016c2148  ascii  mPersonaNamePattern
0x016c67b8  ascii  mEntitlementSource
0x016c68d8  ascii  mPersonaNamespace
0x016c6c38  ascii  mCreatorPersonaName
0x016c6e08  ascii  mHostPersonaName
0x016c73b0  ascii  X-AuthToken
0x016c73e0  ascii  mAuxAuth.mAuthToken
0x016cd2f8  ascii  getUserAccessToken
0x016cd390  ascii  AUTH2_ERR_BANNED_BY_ENTITLEMENT
0x016cd4c8  ascii  getAuthToken
0x016cd500  ascii  getOriginPersona
0x016cd530  ascii  getPersona
0x016cd540  ascii  getPersonaNameSuggestions
0x016cd5a8  ascii  grantEntitlement
0x016cd5c0  ascii  grantEntitlement2
0x016cd5e8  ascii  listEntitlements
0x016cd600  ascii  listPersonaEntitlements2
0x016cd620  ascii  listPersonas
0x016cd630  ascii  listUserEntitlements2
0x016cd650  ascii  modifyEntitlement2
0x016cd6f8  ascii  validateSessionKey
0x016cd840  ascii  AUTH_ERR_PERSONA_NOT_FOUND
0x016cd860  ascii  AUTH_ERR_PERSONA_INACTIVE
0x016cd900  ascii  AUTH_ERR_PERSONA_BANNED
0x016cd918  ascii  AUTH_ERR_INVALID_PERSONA
0x016cdaa0  ascii  AUTH_ERR_MISSING_PERSONAID
0x016cdac0  ascii  AUTH_ERR_USER_DOES_NOT_MATCH_PERSONA
0x016cdb00  ascii  AUTH_ERR_LINK_PERSONA
0x016cdb30  ascii  AUTH_ERR_NO_SUCH_ENTITLEMENT
0x016cdc28  ascii  AUTH_ERR_ENTITLEMENT_TAG_REQUIRED
0x016cdcd0  ascii  AUTH_ERR_UNKNOWN_ENTITLEMENT
0x016cdd98  ascii  AUTH_ERR_PERSONA_EXTREFID_REQUIRED
0x016cde38  ascii  AUTH_ERR_NO_SUCH_PERSONA_REFERENCE
0x016ce140  ascii  AUTH_ERR_TOO_MANY_PERSONA_FOR_NAMESPACE
0x016d0b18  ascii  SDK_ERR_NUCLEUS_RESPONSE
0x016d0eb8  ascii  LoginData::mPersonaDetailsList
0x016d9198  ascii  LOGOUT_TYPE_PERSONA
0x016dad20  ascii  mOriginPersonaId
0x016dafd8  ascii  PERSONA_NAME
0x016db030  ascii  ORIGIN_PERSONA_ID
0x016e7de8  ascii  uploadEntitlements
0x016f7268  ascii  mEntitlementSearchParams
0x016f7348  ascii  mEntitlement
0x016f74d0  ascii  mEntitlementUri
0x016f7650  ascii  mEntAuthPersonaUri
0x016f7bc8  ascii  mShowPersona
0x016f80f8  ascii  mPersonaUri
0x016f8170  ascii  mPersonas
0x017092b0  ascii  mAuthCredentials.mAccessToken
0x017092d0  ascii  X-NUCLEUS-USER-IP
0x01709338  ascii  /personas/
0x01709348  ascii  personaId
0x01709358  ascii  /proxy/identity/pids/{pid}/personas/{personaId}
0x017093a0  ascii  /entitlements
0x017093d8  ascii  mEntitlementSearchParams.mGroupNames
0x01709400  ascii  mEntitlementSearchParams.mStatus
0x01709440  ascii  mEntitlementSearchParams.mStatusReasonCode
0x01709470  ascii  hasAuthorizedPersona
0x01709488  ascii  mEntitlementSearchParams.mHasAuthorizedPersona
0x017094c8  ascii  mEntitlementSearchParams.mProjectId
0x017094f0  ascii  entitlementTag
0x01709500  ascii  mEntitlementSearchParams.mEntitlementTag
0x01709530  ascii  mEntitlementSearchParams.mProductId
0x01709568  ascii  mEntitlementSearchParams.mStartGrantDate
0x017095a8  ascii  mEntitlementSearchParams.mEndGrantDate
0x017095e8  ascii  mEntitlementSearchParams.mEndTerminationDate
0x01709628  ascii  mEntitlementSearchParams.mProductCatalog
0x01709658  ascii  entitlementType
0x01709668  ascii  mEntitlementSearchParams.mEntitlementType
0x017096b0  ascii  mEntitlementSearchParams.mStartTerminationDate
0x017096e0  ascii  /proxy/identity/pids/{pid}/entitlements
0x01709708  ascii  /proxy/identity/entitlements/
0x01709728  ascii  entitlementId
0x01709738  ascii  /proxy/identity/entitlements/{entitlementId}
0x01709768  ascii  /proxy/identity/personas/
0x01709788  ascii  /proxy/identity/personas/{personaId}/entitlements
0x017097c0  ascii  /proxy/identity/personas
0x01709848  ascii  /personas
0x01709890  ascii  /proxy/identity/pids/{pid}/personas
0x01709910  ascii  entitlementInfo
0x01709920  ascii  /proxy/identity/entitlements/{entitlementId}/personas/{personaId}
0x01709980  ascii  /entitlements/searchorcreate
0x017099a0  ascii  /proxy/identity/pids/{pid}/entitlements/searchorcreate
0x017099d8  ascii  personaInfo
0x0170bc68  ascii  QUERY_ENTITLEMENTS_COMPLETE_EVENT
0x0170bd00  ascii  CONSUME_ENTITLEMENT_COMPLETE_EVENT
```

## netcode (364)

_P2P gameplay - topology, NAT, AllDrive. Important for phases 2 and 5._

```
0x003153ef  ascii  O:qOS
0x00496f6d  ascii  <qos
0x006d2424  ascii  Nat%
0x00b5feb9  ascii  MnqoS
0x00c4e543  ascii  qoS?9
0x00f4ff20  ascii  sqoS
0x010e1b0f  ascii  qos%$~
0x0111f438  ascii  t~lqOs
0x013d1cb8  ascii  Looping
0x013d95a8  ascii  PositiveDamping
0x013d95b8  ascii  NegativeDamping
0x013dc1a8  ascii  GestureMapping
0x013dd100  ascii  Stopping on
0x013dd2a8  ascii  Stopping
0x013dd2c8  ascii  #Not stopping
0x013e00c8  ascii  Damping
0x013e19a8  ascii  InwardsDamping
0x013e1a88  ascii  OutwardsDamping
0x013f23f0  ascii  DataBusPeer
0x013f25f0  ascii  LatencyMin
0x013f2640  ascii  LatencyMax
0x01400dc8  ascii  RandomSessionId
0x01404840  ascii  Mesh
0x01407ff8  ascii  EmittableType_Mesh
0x014080c8  ascii  ParticleMesh
0x0141a0d8  ascii  EntityBusPeer
0x0141b4b8  ascii  CustomSequenceTrackPropertyMapping
0x0141beb8  ascii  CustomSequenceTrackLinkMapping
0x0141bfd8  ascii  CustomSequenceTrackEventMapping
0x014251f0  ascii  ClientJoinMultiplayerMessageBase
0x01425648  ascii  ClientStartMultiplayerMessage
0x0145e0f0  ascii  multiplayer
0x01460d50  ascii  NetworkJuiceSessionMessage
0x01461168  ascii  SessionPlayerLeftMessage
0x01461240  ascii  SessionPlayerAuthenticatedMessage
0x01461288  ascii  SessionPlayerJoinedMessage
0x0146a700  ascii  OccluderMesh
0x0146a918  ascii  Session_PlayerJoined("
0x0146a930  ascii  Session_PlayerLeft("
0x0146a948  ascii  Session_PlayerAuthenticated("
0x01489c88  ascii  PersistenceGameType_Multiplayer
0x0148a300  ascii  PersistenceConsumableMapping
0x0148a688  ascii  PlayerCountNeededForMultiplayer
0x0148e868  ascii  IsLooping
0x0148f9f0  ascii  InputMapping
0x014906b0  ascii  IsMultiplayer
0x01490c70  ascii  MaxAllowedLatency
0x01491870  ascii  ForceMultiplayerOneTickMin
0x014946f8  ascii  FaceAnimationWaveMapping
0x014996b8  ascii  DisableFiringWhileJumping
0x0149baf8  ascii  LinearDamping
0x0149bb50  ascii  AngularDamping
0x014a22e8  ascii  IsMultiplayerLayer
0x014a2478  ascii  LanguageMapping
0x014a4028  ascii  WeaponMesh
0x014a4a80  ascii  UITextureMapping
0x014ab778  ascii  EnableCameraMesh
0x014abd50  ascii  CockpitMesh
0x014abd60  ascii  ForegroundRenderCockpitMesh
0x014b1270  ascii  ExtraDamping
0x014bd568  ascii  NonZRotDamping
0x014bdd68  ascii  AngularMomentumDamping
0x014bee38  ascii  EndDamping
0x014befe8  ascii  SpringDamping
0x014bf138  ascii  VmStopping
0x014bfc00  ascii  KickstandLinearDamping
0x014c02f8  ascii  WheelieSpringDamping
0x014c03a8  ascii  WheelieAngularDamping
0x014c1880  ascii  SteerFFBRemapping
0x014c24c0  ascii  MotionDamping
0x014c3500  ascii  UseAngularMomentumDamping
0x014c3728  ascii  AngularVelocityDamping
0x014c3740  ascii  LinearVelocityDamping
0x014c7690  ascii  Time_to_blend_damping
0x014c7ac0  ascii  Default_steering_remapping
0x014c7af8  ascii  Counter_steering_remapping
0x014c7be0  ascii  CharacterStateType_Jumping
0x014c7e30  ascii  Drift_sideways_damping
0x014c7f60  ascii  Drift_angular_damping
0x014c8c00  ascii  ClothSectionMapping
0x014d8f50  ascii  Mesh/VertexAnimation/
0x014d9008  ascii  Mesh/Standard/
0x014d9018  ascii  Mesh/
0x014d9510  ascii  Systems/Mesh/DefaultShader
0x014de5b8  ascii  ShaderTessellationType_DisplacementMapping
0x014e6900  ascii  The application's remote device has been removed due to session disconnect or network disconnect. The application should call IDXGIFactory1::IsCurrent to find out when the remote device becomes available again.
0x014e7788  ascii  Systems/Shader/DisplacementMapping
0x014f5638  ascii  UIAudioEventMapping
0x014f59f0  ascii  UIFontMapping
0x014fc208  ascii  vegetationMesh
0x014fc218  ascii  vegetationShadowMesh
0x014fc400  ascii  ShadowMesh
0x014ff240  ascii  occluderMesh
0x015156b0  ascii  UseNavMesh
0x01522c48  ascii  sessionCount
0x01526368  ascii  ClientHostMigrationManagerEntity
0x01548c68  ascii  %SESSION%
0x01551da0  ascii  ClientAllDriveProxyEntity
0x01551e50  ascii  ClientAllDriveEntity
0x01555c30  ascii  alldrive_profile_frame
0x0155e160  ascii  ClientStartMultiplayerEntity
0x01560d78  ascii  ClientSessionStatsEntity
0x01576ec0  ascii  ClientUIAllDrivePlayersWidgetEntity
0x01579320  ascii  AllDriveProfilePicture
0x01579338  ascii  AllDriveFrame
0x015793a0  ascii  alldrive_empty_slot
0x0159e170  ascii  ClientUIAllDrivePointOfInterestProviderEntity
0x015a31c0  ascii  ClientUIAllDriveHudMessageCollectorProxyEntity
0x015a32b0  ascii  ClientUIAllDriveHudMessageCollectorEntity
0x015a34f8  ascii  ClientUIAllDriveHudNotificationEntity
0x015ac0c8  ascii  ClientUISubMenuSessionStoryVideoWidgetEntity
0x015ac0f8  ascii  ClientUIMenuSessionSummaryEntryEntity
0x015ac180  ascii  ClientUIMenuSessionSummaryIntEntryEntity
0x015ac230  ascii  ClientUIMenuSessionSummaryFloatEntryEntity
0x015ac3e0  ascii  ClientUISubMenuSessionUnlockVideoWidgetEntity
0x015ac4e0  ascii  ClientUISubMenuSessionUnlockWidgetEntity
0x015ac538  ascii  ClientUISubMenuSessionSummaryWidgetEntity
0x015b5ec0  ascii  ID_NO_MULTIPLAYER_PRIVILEGES
0x015c6d88  ascii  StartMultiplayerEntityData
0x015c9440  ascii  MULTIPLAYER_ENABLED
0x015cb880  ascii  WaitingForHostMigration
0x015cc660  ascii  MultiplayerGameState
0x015cc678  ascii  HostMigration
0x015cd160  ascii  UIAllDriveNotificationMessage
0x015cea50  ascii  AllDriveRadius
0x015cea60  ascii  AllDriveExitLifetime
0x015cea78  ascii  AllDriveEntityData
0x015ceae8  ascii  AllDriveProxyEntityData
0x015d0f40  ascii  EVENT_PLAYER_SESSION_START
0x015d0f60  ascii  EVENT_PLAYER_SESSION_PAUSE
0x015d0f80  ascii  EVENT_PLAYER_SESSION_RESUME
0x015d0fa0  ascii  EVENT_PLAYER_SESSION_END
0x015d0fc0  ascii  EVENT_MULTIPLAYER_ROUND_START
0x015d0fe0  ascii  EVENT_MULTIPLAYER_ROUND_END
0x015d2080  ascii  AllDriveIconTextureId
0x015d20c8  ascii  UIAllDrivePointOfInterestProviderEntityData
0x015d59f8  ascii  icon_alldrive
0x015d9288  ascii  UIAllDrivePlayersWidgetEntityData
0x015df420  ascii  UIAllDriveHudNotificationEntityData
0x015df5c8  ascii  UIAllDriveHudMessageCollectorEntityData
0x015df6c8  ascii  UIAllDriveHudMessageCollectorProxyEntityData
0x015e2938  ascii  UISubMenuSessionSummaryWidgetEntityData
0x015e2b70  ascii  UISubMenuSessionUnlockVideoWidgetEntityData
0x015e2c10  ascii  SpeedWallTypeTextureMapping
0x015e2c58  ascii  UISubMenuSessionUnlockWidgetEntityData
0x015e2ca8  ascii  SpeedwallToTextureIdMapping
0x015e2cc8  ascii  UIMenuSessionSummaryEntryEntityData
0x015e2d90  ascii  UIMenuSessionSummaryIntEntryEntityData
0x015e2de8  ascii  UISubMenuSessionStoryVideoWidgetEntityData
0x015e2e50  ascii  PlaylistIconTypeTextureMapping
0x015e2e90  ascii  UIMenuSessionSummaryFloatEntryEntityData
0x015e2ef0  ascii  PlaylistIconToTextureIdMapping
0x015e3000  ascii  ShowSessionSummary
0x015ecb10  ascii  HostMigrationManagerEntityData
0x015f0ea8  ascii  WreckedMesh
0x015f1fd0  ascii  EnableMesh
0x015f6800  ascii  MaterialMapping
0x015f9d78  ascii  OriginMultiplayerId
0x015fdae8  ascii  AllDriveMultiplier
0x015fdbb8  ascii  ScoreIsSessionBased
0x01601b48  ascii  LoadedSessionInProgress
0x01601d00  ascii  SessionStatsEntityData
0x01603fd0  ascii  SteeringDamping
0x01603fe0  ascii  BrakeDamping
0x01603ff0  ascii  HandbrakeDamping
0x016061e8  ascii  RenderMesh
0x0162f660  ascii  ServerHostMigrationManagerEntity
0x01651450  ascii  Warning: GFxLoader - GFxStream-end tag hit, but not at the end of the file yet; stopping for safety
0x0165d628  ascii  GFxMesh::Display
0x01671a40  ascii  while parsing a block mapping
0x01671ad0  ascii  while parsing a flow mapping
0x01671c50  ascii  mapping keys are not allowed in this context
0x01671c80  ascii  mapping values are not allowed in this context
0x016767f8  ascii  EA::BugSentry::SessionReportUploader
0x016769c8  ascii  session
0x01676a90  ascii  sessionid
0x0167e7cc  ascii  MESH
0x01681bf0  ascii  linearDamping
0x01681c00  ascii  angularDamping
0x01684570  ascii  Y:\Build\20121203_205832_StandardPackages\Source\Common/Internal/GeometryProcessing/Mesh/hkgpMesh.h
0x016846a8  ascii  GeometryProcessing\Mesh\hkgpMesh.cpp
0x01684718  ascii  Invalid mesh topology (
0x016886f0  ascii  damping
0x0168acb8  ascii  EXTENDED_MESH
0x0168acd8  ascii  COMPRESSED_MESH
0x0168acf8  ascii  BV_COMPRESSED_MESH
0x0168c7a0  ascii  hkcdShapeType::COMPRESSED_MESH
0x0168ca60  ascii  hkcdShapeType::EXTENDED_MESH
0x0168caa0  ascii  hkcdShapeType::BV_COMPRESSED_MESH
0x0168ef88  ascii  COLLECTION_EXTENDED_MESH
0x0168efe0  ascii  COLLECTION_SIMPLE_MESH
0x0168f010  ascii  COLLECTION_COMPRESSED_MESH
0x0168fba8  ascii  BVTREE_COMPRESSED_MESH
0x01697ea0  ascii  inverseMapping
0x01697f28  ascii  hkpBreakableMultiMaterialInverseMapping
0x01697f50  ascii  !hkpBreakableMultiMaterial::InverseMapping
0x0169c4f0  ascii  K:\Other\DevRel\Clients\DICE\Frostbite\2012_2_0\Source\Physics/Internal/Collide/BvCompressedMesh/hkpBvCompressedMeshShapeInternals.inl
0x0169cbf0  ascii  Collide\BvCompressedMesh\hkpBvCompressedMeshShape.cpp
0x0169dda0  ascii  Invalid geometry from hkShape display geometry data. Skipping it.
0x016a25f0  ascii  MultiplayerInvite
0x016a2608  ascii  MultiplayerInvitePending
0x016a7128  ascii  MULTIPLAYER
0x016a8730  ascii  MultiplayerId
0x016a8780  ascii  SessionId
0x016a87f8  ascii  SessionInformation
0x016a9fb0  ascii  ?session=
0x016ae168  ascii  mSessionInfo
0x016b1080  ascii  SessionInfo
0x016b9900  ascii  CLUBS_MEMBER_IN_OPEN_SESSION
0x016b9a00  ascii  UPDATE_REASON_USER_SESSION_CREATED
0x016b9a40  ascii  UPDATE_REASON_USER_SESSION_DESTROYED
0x016c7390  ascii  mSessionID
0x016cd8e0  ascii  AUTH_ERR_INVALID_SESSION_KEY
0x016ce230  ascii  AUTH_ERR_NO_PARENT_SESSION
0x016cfc70  ascii  resumeSession
0x016cfd30  ascii  USER_ERR_SESSION_NOT_FOUND
0x016cfd50  ascii  USER_ERR_DUPLICATE_SESSION
0x016cfdc8  ascii  USER_ERR_INVALID_SESSION_INSTANCE
0x016cfe38  ascii  USER_ERR_RESUMABLE_SESSION_CONNECTION_INVALID
0x016cfe68  ascii  USER_ERR_RESUMABLE_SESSION_NOT_FOUND
0x016d0148  ascii  ping
0x016d01c8  ascii  suspendUserPing
0x016d06d8  ascii  ERR_GUEST_SESSION_NOT_ALLOWED
0x016d08a0  ascii  SDK_ERR_NO_MULTIPLAYER_PRIVILEGE
0x016d9360  ascii  mHostMigrationType
0x016d9378  ascii  mExternalSessionTemplateName
0x016d97b0  ascii  mXnetSession
0x016d9968  ascii  mSessionId
0x016d9f30  ascii  SESSION_TIMED_OUT
0x016d9f48  ascii  SESSION_CANCELED
0x016d9f78  ascii  SESSION_TERMINATED
0x016d9fa0  ascii  SESSION_ERROR_GAME_SETUP_FAILED
0x016d9fc0  ascii  mExternalSessionCorrelationId
0x016da040  ascii  mSessionDurationMS
0x016da148  ascii  mExternalSessionName
0x016daa70  ascii  PLAYER_JOIN_EXTERNAL_SESSION_FAILED
0x016dab80  ascii  EXTERNAL_SESSION_GAME
0x016dac08  ascii  TOPOLOGY_HOST_MIGRATION
0x016dac38  ascii  TOPOLOGY_PLATFORM_HOST_MIGRATION
0x016dac88  ascii  USER_SESSION_NORMAL
0x016dacc0  ascii  USER_SESSION_GUEST
0x016dad60  ascii  mCachedExternalSessionToken
0x016dae08  ascii  mNpSessionId
0x016daee8  ascii  mLatencyList
0x016db150  ascii  mHasJoinFirstPartyGameSessionPermission
0x016db178  ascii  mNumOfLoggedSession
0x016de960  ascii  ResumeSessionRequest
0x016dfc80  ascii  UpdateGameSessionRequest
0x016dfd50  ascii  UpdateGameHostMigrationStatusRequest
0x016e15f0  ascii  NotifyHostMigrationStart
0x016e16c0  ascii  NotifyHostMigrationFinished
0x016e2230  ascii  GameSessionUpdatedNotification
0x016e4d38  ascii  mTopologyHostSessionId
0x016e4d50  ascii  mNetworkTopology
0x016e4d98  ascii  mExternalSessionId
0x016e4de0  ascii  mVoipTopology
0x016e4e80  ascii  mPlayerSessionId
0x016e50a0  ascii  mTopologyHostInfo
0x016e54a0  ascii  mSessionLength
0x016e54e0  ascii  mSessionStart
0x016e5c10  ascii  mSessionMode
0x016e89e0  ascii  updateGameHostMigrationStatus
0x016e8a10  ascii  updateGameSession
0x016e99b8  ascii  NotifyGameSessionUpdated
0x016f72c0  ascii  mSessionChanging
0x016f7608  ascii  mSourceSessionIds
0x016fa400  ascii  NotifyXboxSessionInfo
0x017057f0  ascii  mPingSiteLatencyByAliasMap
0x01705858  ascii  UPNP_UNKNOWN
0x01705868  ascii  UPNP_FOUND
0x01705878  ascii  UPNP_ENABLED
0x01705a40  ascii  VOIP_PEER_TO_PEER
0x01705aa0  ascii  PEER_TO_PEER_FULL_MESH
0x01705ab8  ascii  PEER_TO_PEER_PARTIAL_MESH
0x01706e58  ascii  mNumLatencyProbes
0x01706e98  ascii  NetworkInfo::mPingSiteLatencyByAliasMap
0x01709f38  ascii  NotifyXboxSessionChange
0x0170c770  ascii  -noupnp
0x0170d860  ascii  %s://%s:%u/qos/firewall?vers=%d
0x0170d888  ascii  %s://%s:%u/qos/firetype?vers=%d
0x0170d8c8  ascii  %s://%s:%u/qos/qos?vers=%d
0x0170de40  ascii  ST:urn:schemas-upnp-org:device:WANConnectionDevice:1
0x0170dea8  ascii  urn:schemas-upnp-org:device:wanconnectiondevice
0x0170e030  ascii  %*:Envelope.%*:Body.%*:Fault.detail.UPnPError
0x0170e248  ascii  AddPortMapping
0x0170e300  ascii  DeletePortMapping
0x0170e930  ascii  Cookie: sessionID=%s
0x0170eab0  ascii  &latency=%d
0x01711440  ascii  This attribute specifies the reverberation time in seconds. It is a measure of the time it takes the reverberation of a given sound to decay. Longer times would, for example, tend to be associated with highly reflective walls or surfaces. A value of 0 results in turning the reverb off, and stopping audio output from the associated voice. The minimum non-zero reverb time is 0.366 seconds, and values between this and 0 are clamped to it (0.366).
0x0171248f  ascii  A value of 0.0 will stop playback entirely. Note that in this case the sample at the current playback position will be repeated until the pitch is set to anything but 0.0. This can create a DC offset when the resulting signal is mixed in with other audio, which can in turn cause clipping distortion. If the pitch is set to 0.0, then gain for the voice should also be set to 0.0 to avoid this DC offset. If pitch is being zeroed to achieve a type of pause functionality, it is recommended that users employ the Pause PlugIn instead. 
0x01712b00  ascii  Unlike most other PlugIns, pitch change using Resample can only be performed in source voices. This is because pitch changes affect the rate at which samples are requested or produced from the upstream signal chain. In order to keep the general purpose PlugIn case simple and also solve various other pitch synchronization issues, EAAudioCore only allows pitch changes near the top of the source voice. After that, all sample data is at a uniform sample rate, which makes processing it far simpler. This restriction has ramifications for the various end users and other technology control layers used to drive EAAudioCore. Instead of being able to simply plunk down one or more pitch controls on source and submix voices, to achieve desired effects such as singular control at a submix point and doppler, control layers must maintain a virtual mapping of all the desired control points, compute a final pitch for each source voice, and apply it.
0x017139a0  ascii  This constructor parameter specifies if an envelope can be used. An envelope may be used to dynamically change a reverb while using the same reverb file. Enabling the use of an envelope will result in a small amount of memory being allocated for enveloping purposes, the size of which depends on how long the reverb files are. An envelope scales the reverb file from the beginning of the impulse response with a starting gain set by the envelope start level attribute (i.e., ATTRIBUTE_REVERB0ENVELOPESTARTLEVEL for reverb0) down to a gain of zero. The gain decreases based on the envelope type (i.e., ATTRIBUTE_REVERB0ENVELOPETYPE for reverb0), which currently can be either linearly or exponentially shaped. Envelope duration is set by the envelope length attribute (i.e., ATTRIBUTE_REVERB0ENVELOPELENGTH for reverb0), which specifies in seconds the time over which the envelope decays from its starting gain to zero. 
0x01713f30  ascii  This attribute specifies the type of envelope to use for the first reverb. This and all other envelope related attributes is respected only when enveloping is enabled at construction time (ENVELOPINGMODEPARAM_ENABLE).
0x01714060  ascii  This attribute specifies the start level of the first envelope. A value of 1.0 means that the envelope will start at a normal level, while 2.0 signifies a start level of double the normal level. This and all other envelope related attributes is respected only when enveloping is enabled at construction time (ENVELOPINGMODEPARAM_ENABLE).
0x01714200  ascii  This attribute specifies the length of the first reverb's envelope. At the end point of the envelope the gain will have decayed to 0. This and all other envelope related attributes is respected only when enveloping is enabled at construction time (ENVELOPINGMODEPARAM_ENABLE).
0x01714350  ascii  This attribute specifies the type of envelope to use for the second reverb. This and all other envelope related attributes is respected only when enveloping is enabled at construction time (ENVELOPINGMODEPARAM_ENABLE).
0x01714480  ascii  This attribute specifies the start level of the second envelope. A value of 1.0 means that the envelope will start at a normal level, while 2.0 signifies a start level of double the normal level. This and all other envelope related attributes is respected only when enveloping is enabled at construction time (ENVELOPINGMODEPARAM_ENABLE).
0x01714620  ascii  This attribute specifies the length of the second envelope. At the end point of the envelope the gain will have decayed to 0. This and all other envelope related attributes is respected only when enveloping is enabled at construction time (ENVELOPINGMODEPARAM_ENABLE).
0x01714a4f  ascii  Note: On little endian platforms (e.g. PC, iOS, Android), the reverb file memory may not be used by more than a single PlugIn instance at a time. This is because it is initially written to by the PlugIn until endian swapping has been completed. Sharing is particularly unsafe in multicore mixing mode, though we don't normally expect users to run multiple instances of the PlugIn given its high cost.
0x01715acb  ascii  The ReverbIR1 PlugIn also supports the enveloping of either or both of the impulse responses. This allows for the possibility of shortening a given impulse response by fading it out to zero over a specified amount of time (i.e., ATTRIBUTE_REVERB0ENVELOPELENGTH for reverb 0).A start gain and envelope shape also must be specified via attributes (i.e., ATTRIBUTE_REVERB0ENVELOPESTARTLEVEL and ATTRIBUTE_REVERB0ENVELOPETYPE for reverb 0 respectively). This enveloping feature should be used with care, as the artificial shortening of an impulse response with a ramp does not exactly reflect a real-world scenario. If employed, users should experiment with the various enveloping parameters and impulse response(s) to confirm the resulting reverb suits their needs. The potential benefit with the use of enveloping is that it provides the user with some control over a given impulse response, allowing for greater variability and/or the use of less impulse response files. In the extreme, a user might use a single long impulse response, and simply adjust its length via enveloping to tailor it to the various reverberent spaces of the game. Combining enveloping with the use of two active individually gained reverb files can result in a high degree of flexibility and real-time creative control. 
0x01718400  ascii  Unlike most other PlugIns, pitch change using ResampleHQ can only be performed in source voices. This is because pitch changes affect the rate at which samples are requested or produced from the upstream signal chain. In order to keep the general purpose PlugIn case simple and also solve various other pitch synchronization issues, EAAudioCore only allows pitch changes near the top of the source voice. After that, all sample data is at a uniform sample rate, which makes processing it far simpler. This restriction has ramifications for the various end users and other technology control layers used to drive EAAudioCore. Instead of being able to simply plunk down one or more pitch controls on source and submix voices, to achieve desired effects such as singular control at a submix point and doppler, control layers must maintain a virtual mapping of all the desired control points, compute a final pitch for each source voice, and apply it.
0x0171cc8b  ascii  As this PlugIn is primarily meant for debugging, it is not recommended to use it in shipping games at this time, as it is not implemented in an efficient manner. The synchronous nature of the ANSI file writing calls used here makes it quite possible the EAAudioCore audio thread will be stalled and a buffer underrun will occur (crackling audio). The chance of this happening is likely going to depend on what device is being written to.
0x0171ce42  ascii  Before the sample data is written, it is hard clipped. If a loud signal was coming in, you will most likely see hard clipping.
0x0171d9a0  ascii  The BandPassIir2 PlugIn allows for the relatively inexpensive band pass filtering of a signal. The filter provides zero dB gain in the pass band, and a transition band roll-off of at least 12 dB per octave.The filter uses feed-forward and feed-back elements, and as such can be classified as an Infinite Impulse Response (IIR) filter. The filter is second order, with 2 non-trivial poles and zeros. Given its IIR nature, the phase response of the filter is non-linear; though the degree of non-linearity in the pass band is not severe. Filter stability is assured by clamping the cutoff frequency (internally) to always be BETWEEN zero Hertz and the Nyquist frequency (one half the sample rate), and the bandwidth to be greater than zero.
0x0172333a  ascii  For the PC, this output mode is not recommended to be used in game code. The 7.1 signal is folded down by dropping the LFE, dropping the backs and center by 3 dB and mixing them with the front left and front right, and then bringing the entire mix down an additional 3 dB. For the listed mobile platforms other then Android, this mode can be set via EVENT_SETMODE. For Android, the mode cannot be set via EVENT_SETMODE, but rather is set via the Java code AndroidEAAudioCore.Startup(channels).
0x01723956  ascii  On the PC where EAAudioCore is in charge of handling the fold down from 7.1 to stereo, an accepted standard for mixing the signals together is used. The LFE is dropped, the backs and far backs are lowered by 3 dB and mixed with the fronts, and the center channel is mixed in with the fronts at equal power (down 3 dB). The entire mix is then brought down an additional 3 dB to keep the signal from running too hot and clipping excessively where it wouldn't have in the 7.1 mix. Similar algorithms are likely used on platforms where the console itself is in charge of fold down (e.g. Xbox 360 and PS3), and they seem to produce the same results as EAAudioCore on PC. However, it is possible there may be slight differences, since the details of those algorithm implementations are not public.
0x01726ab8  ascii  ATTRIBUTE_GETLATENCY
0x01726ad0  ascii  Latency
0x01726ae0  ascii  This attribute indicates how much latency in time the Dac PlugIn adds between making an EAAudioCore call, and when the results of the action are heard out of the speakers (e.g. from the time a sample is triggered with an EAAudioCore call and the time it begins being heard out of the speakers). The units are in seconds.
0x01726c22  ascii  Users should note that other PlugIns in the mix can also add delay, and that the total latency at any point in the mix is equal to the summation of all latencies from that point through to the Dac output. To obtain the latencies associated with this PlugIn processing through the mix, users should call Voice::GetLatency() on the applicable Voices and sum the results for each chain that is of interest (please refer to the documentation on Voice::GetLatency() for more details). The latency reported via ATTRIBUTE_GETLATENCY is only that associated with buffering the mixed output audio. In an ideal world, there would be no latency between triggering an action and hearing it out of the speakers. On platforms such as the PC considerable latency (e.g. up to 300 milliseconds) can be introduced because the PC is not a real-time system. In non-System Jobs mode, the latency will vary on the PC as there is dynamic compensation based on how "real-time" the PC is acting at the moment. On other platforms latency is not much of an issue when not operating in System Jobs mode. When in System Jobs mode, however, the latency on all platforms may be longer if User Scheduling is being used in order to schedule EAAudioCore jobs from the user thread at a lower rate (say 30 or 60 Hz) than the EAAudioCore frame rate (187.5 Hz at a 48 KHz sample rate). In those cases, ATTRIBUTE_GETLATENCY will be on the order of the target mix ahead set when operating in that mode (as set by System::SetTargetMixAhead()), though generally less since the mix ahead is a target or maximum value. 
0x0172724b  ascii  Latency can be an important factor when trying to synchronize other game concepts such as animation or video to audio. If the latency is not taken into account and the Dac is adding say 300 milliseconds of latency, the video will be out of sync with the audio by 300 milliseconds. This might make for an unpleasant end user experience. Game code and other systems should get around this by compensating for the latency introduced. For example, if the total latency was 300 milliseconds, then 300 milliseconds should be subtracted from the current playback position of a sample being played which is being synchronized. In the PC non-System Jobs mode case where dynamic compensation is being used, the current latency must be subtracted from the sample playback position each time it is polled in order to avoid any drift associated with latency changes. This will keep the audio and video in sync.
0x017275d0  ascii  ATTRIBUTE_SETENABLECLIPPING
0x017275f0  ascii  Clipping
0x01727600  ascii  This attribute specifies whether or not to enable hard clipping by the Dac PlugIn. The default is set to true for backward compatibility. For platforms with lower end processors, the attribute provides a way to save CPU cycles by turning off clipping. This should only be done if users have ensured that the final Dac audio output is never in need of clipping by staying within the range of +/- 1.0, and/or they have confirmed that the platform(s) being used employs its own clipping. In this latter case where platforms automatically provide their own clipping, the Dac PlugIn will not do any additional clipping and so this attribute is ignored.
0x01727889  ascii  Currently the following platforms are known to do their own clipping:
0x017293d2  ascii  For Android, the output mode selection is handled via Java code AndroidEAAudioCore.Startup (channels).When a channel configuration with more channels than what the output is set to is fed to the Dac, it will perform an industry standard fold-down to the required configuration (5.1, quad, stereo or mono). Even if the Dac PlugIn is not performing the fold-down, the PC or console platform might be performing a fold-down on its end. Hard clipping can be introduced during the fold-down if the signal coming into the fold-down is loud. Although the hard clipping should not be as audible a problem as it might sound, it can be avoided by reducing the volume of the signal before it goes into the Dac PlugIn. If a signal is normalized to full scale (+/- 1.0) before it enters the Dac PlugIn by a PlugIn such as a compressor, then when folding down to quad or stereo, reducing the signal to approximately 45% (-6.9 dB) of its original level will ensure no hard clipping will occur. On the other hand, hard clipping noise is not as noticeable as one might think. Furthermore, given that it may be quite unlikely that the mix will be driven in game to produce the extreme configuration required to produce the maximum peak (greater than +/- 1.0) after fold-down, it is suggested that users not worry too much about clipping possibilities, especially since the additional reduction of volume to avoid it may result in the game output being too quiet.
0x01733310  ascii  Hard clipping.
0x0173450f  ascii  Note also that it is possible to explicitly set a start gain prior to a given fade. This can be achieved by specifying a fade of duration 0 with a start time of 0 and an end gain equal to the gain value desired. This will only take if both these parameters (fadeTime and startTime) are set to 0. One example of when this feature might be useful is if the user wants to ramp up a signal from 0 but the current gain of the fader is not 0, such as at PlugIn startup (when the gain is set to 1). In this case, the user would specify two fades in succession, one to set the current gain to 0, and a second one to initiate the ramping up of the signal. Since the user may require that the initial gain setting (to 0 in this case) not delay the subsequent signal ramp up, both these gain fade events may be applied within the same lock (EA::Audio::Core::Lock()/Unlock()). As such, it is a special case, since otherwise the Gain Fader does not support queuing of gain fade events. It should also be noted that this feature should be used with extreme caution, since changing the gain value over a fade duration of 0 will introduce a click if the PlugIn is passing a signal at the time the gain is changed. It should only be used if there is no signal being passed or it is known that the current signal amplitude is 0.
0x017370ce  ascii  The GenericPlayer supports playback of samples either loaded into RAM or streamed through the filesystem. Stiched playback and sample accurate starting are also possible when supported by the file format being played. Currently, there is no support for looping or seeking. Assets with loop points will simply play out once.
0x0173b770  ascii  The HighPassIir2 PlugIn allows for the relatively inexpensive high pass filtering of a signal. The filter provides zero dB gain in the pass band, and a transition band roll-off of at least 12 dB per octave.The filter uses feed-forward and feed-back elements, and as such can be classified as an Infinite Impulse Response (IIR) filter. The filter is second order, with 2 non-trivial poles and zeros. Given its IIR nature, the phase response of the filter is non-linear; though the degree of non-linearity in the pass band is not severe. Filter stability is assured by clamping the cutoff frequency (internally) to always be BETWEEN zero Hertz and the Nyquist frequency (one half the sample rate).
0x0173d332  ascii  Although there is no restriction on mapping more than one HwFxReturn1 to the same effect bus, it is recommended that only one be mapped per bus to minimize the overall CPU load.Currently HwFxReturn1 is only supported on the Cafe platform. 
0x0173ddaf  ascii  A value of 0.0 will stop playback entirely. Note that in this case the sample at the current playback position will be repeated until the pitch is set to anything but 0.0. This can create a DC offset when the resulting signal is mixed in with other audio, which can in turn cause nasty clipping and other distortion. If the pitch is set to 0.0, then gain for the voice should also be set to 0.0 to avoid this DC offset.
0x0173e37a  ascii  Although there is no restriction on mapping more than one HwFxReturn to the same effect bus, it is recommended that only one HwFxReturn be mapped per effect bus to minimize the overall CPU load. 32 kHz samples are returned, and up to 8 mono effect busses are supported. This PlugIn is operational on the Wii platform only, doing nothing on all other platforms. For the Cafe platform, the HwFxReturn1 PlugIn is to be used instead. Any new platforms that require the return of audio hardware busses will use the HwFxReturn1 PlugIn if possible. This PlugIn (HwFxReturn) will eventually be deprecated if and when Wii platform support is dropped. 
0x0174034a  ascii  Note that any sample requests with loop points in them will prevent subsequent requests from playing properly since a looping sample will never end (unless stopped with EA::Audio::Core::HwPlayer::EVENT_STOP). Due to other internal implementation details queuing further requests while a looping sample is in the queue is forbidden. An assert will be generated if such an attempt is made. 
0x01740ebb  ascii  Looping samples will repeat their loop section infinitely. There is no lead-out section present which can be triggered.
0x01741297  ascii  For Wii, the hardware supports up to 96 hardware voices. So theoretically, there could be up to 96 hardware voices allocated by various HwPlayer PlugIns at one time. Realistically, however, 96 voices could never be reached in games as the Wii DSP may require processing power for other tasks such as re-sampling, mixing, volume ramping, etc. In the case when its resources are exceeded, the Wii may decide to drop hardware voices to free up some processing power for the DSP. When a hardware voice allocated by the HwPlayer is dropped, the playback will be stopped and the voice that the HwPlayer is inserted in will be expelled.
0x0174376d  ascii  Note that other factors besides the HwPlayer may expel the Voice (prioritization, hardware re-acquiring / dropping hardware voice, etc.), so looking for the EA::Audio::Core::Voice::IsExpelled() signal is a convenient way of testing for a Voice being shut down.
0x017460a0  ascii  The MapChannels PlugIn provides a mechanism for outputting a fixed number of channels so that downstream PlugIns can receive an input with a constant number of channels independent of the number of channels associated with the source data or output modes of the platform.This PlugIn can be used for remapping an output channel to silence or from any input channel.By default, if there are more input channels than output channels, the last channels are droppedto match the number of output channels. Similarly, if there are more output channels than input channels, the last output channels which do not have a corresponding input channel are filled with silence.
0x01747650  ascii  The LowPassIir2 PlugIn allows for the relatively inexpensive low pass filtering of a signal. The filter provides zero dB gain in the pass band, and a transition band roll-off of at least 12 dB per octave.The filter uses feed-forward and feed-back elements, and as such can be classified as an Infinite Impulse Response (IIR) filter. The filter is second order, with 2 non-trivial poles and zeros. Given its IIR nature, the phase response of the filter is non-linear; though the degree of non-linearity in the pass band is not severe. Filter stability is assured by clamping the cutoff frequency (internally) to always be BETWEEN zero Hertz and the Nyquist frequency (one half the sample rate).
0x0174c4aa  ascii  The SampleReader PlugIn is capable of looping, seeking, and stitching but is limited by reader implementations and the file formats involved. For example, looping and sample accurate stitching works well with sps data, but would be problematic for conventional MP3 data.
0x0174eaef  ascii  Note that any sample requests with loop points in them will prevent subsequent requests from playing properly since a looping sample will never end (unless stopped with EA::Audio::Core::SndPlayer1::EVENT_STOP). Due to other internal implementation details queuing further requests while a looping sample is in the queue is forbidden. An assert will be generated if such an attempt is made. Seeking into giga or looped samples is not supported.
0x0174edd3  ascii  Looping samples will repeat their loop section infinitely, there is no lead-out section present which can be triggered.
0x0174fb9f  ascii  Note: Users are recommended to use the EVENT_ISREQUESTDONE to determine when a particular request has completed playback. If you wish to release the Voice immediately after it has played then special care must be taken to prevent cutting off the sample playback prematurely to account for latency and decay time. Using EVENT_EXPEL in conjunction with EA::Audio::Core::Voice::IsExpelled() is the preferred method for determining if samples have finished playing. In the case where the voice instance is to be reused, see documentation for EA::Audio::Core::Voice::GetDecayTime() to understand the potential pitfalls surrounding this issue.
0x01752270  ascii  This parameter is used to indicate how long it has been since the player output any signal data. This value can be used at runtime to determine whether a voice's decay/latency time has expired. Note that this is not a completely fail-safe approach as it can fail when the client has paused the voice during this period or has changed plug-in parameters which affect the latency or decay.
0x01757200  ascii  This value indicates that multiple channels should be processed independently for the purpose of finding the peak correlation points needed for looping and cutting the signal. 
0x01757300  ascii  This value indicates that multiple channels should be combined for the purpose of finding the peak correlation points needed for looping and cutting the signal. 
0x01757f90  ascii  Defines the size in milliseconds of the time stretch algorithm window. The window is the fundamental grouping of samples used by the time stretch algorithm to determine correlation peak locations for the purposes of looping and cutting signal segments. The window must be at least large enough to contain one cycle of the lowest expected frequency component in the signal so that a legitimate peak correlation point can be found. The default window size of 9 milliseconds, for example, corresponds to a period of 111 Hz, so that any signals with a fundamental frequency greater or equal to this can be successfully stretched or contracted by the algorithm.
0x01758270  ascii  Defines whether or not channels are grouped together for the purpose of finding correlation peak locations within the signal. Grouping results in an overall cycle usage comparable to that used in processing a single channel signal, but might result in some audio degradation when applied to signals with uncorrelated channel content.
0x01759198  ascii  The TimeStretch PlugIn supports single and multi-channel operation, even though it is expected that most speech sources being stretched will be single channel. In the case of multi-channel operation, the user can select between MULTICHANNELMODE_INDEPENDENT_CHANNELS and MULTICHANNELMODE_COMBINED_CHANNELS modes at voice construction. These modes differ only in how the correlation points are found for each of the channels. Since this analysis operation is expensive, it is possible to use a kind of mean best correlation point across all channels and thereby save doing the analysis on each channel. This corresponds to the MULTICHANNELMODE_COMBINED_CHANNELS mode, and results in only a slightly higher processing load than what would be experienced in processing a single channel. This mode works well if the different channels all still have a relatively high degree of correlation with each other, such as would be the case if they were all derived from the same speech source, but perhaps have had different effects applied to them, such as different types or amounts of reverberation, filtering, or background noise. In these cases, this mode might also be preferred over the independent channel mode (described below) due to it keeping the stretching and contracting of all channels synchronized. This synchronization occurs because the cut/loop points are identical for all channels, and so all channels will loop or cut at the same times.
0x0175b45b  ascii  On iOS, it is required that AudioSession is initialized before UserMusicArbiter is created.
0x0175e300  ascii  HwSamplePlayer is a PlugIn for hardware voices. Currently it is only supported on Vita. The HwSamplePlayer PlugIn is a player for hardware codecs. Currently we've only provided a reader for the sps file format to allow playback of SndPlayer1 assets. It is capable of looping and stitching, depending on the codecs. Some codecs are uncapable of accurate stitching.
0x0175f94f  ascii  A value of 0.0 will stop playback entirely. Note that in this case the sample at the current playback position will be repeated until the pitch is set to anything but 0.0. This can create a DC offset when the resulting signal is mixed in with other audio, which can in turn cause clipping distortion. If the pitch is set to 0.0, then gain for the voice should also be set to 0.0 to avoid this DC offset. If pitch is being zeroed to achieve a type of pause functionality, it is recommended that users employ the HwPause PlugIn instead. 
0x017663d8  ascii  updateLooping
0x017679e8  ascii  SoundScopeStrategyMapping
0x0176dd28  ascii  SoundWaveStreamingMode_ZeroLatency
0x0176dd60  ascii  SoundWaveStreamingMode_LowLatency
0x0176dda8  ascii  VoiceOverDialogTakeMapping
0x0176df38  ascii  AudioLanguageMapping
0x0176e998  ascii  StreamPoolMapping
0x01775418  ascii  TakeIndexMapping
0x01778db0  ascii  NavProbe called with invalid floating point data.  Skipping.
0x0177b260  ascii  Skipping creation of obstacle %s with blockage flags of zero since it will have no effect
0x0177b2c0  ascii  Skipping creation of obstacle %s with penalty mult of 1 since it will have no effect
0x0177b320  ascii  Skipping creation of obstacle %s with invalid floating point data
0x0177c468  ascii  EnableAggressiveLinkSnapping
0x01780600  ascii  Shape\Deprecated\CompressedMesh\hkpCompressedMeshShapeBuilder.cpp
0x019ec7e0  ascii  WTSRegisterSessionNotification
0x019ec802  ascii  WTSUnRegisterSessionNotification
0x01ce5910  utf16  I&gnore This Session
0x01cedd84  utf16  Juice Session Id:
0x01d08633  ascii  Thawte Timestamping CA0
0x01d086a1  ascii  'Symantec Time Stamping Services CA - G20
0x01d08a65  ascii  +Symantec Time Stamping Services Signer - G40
0x01d09cc2  ascii  'Symantec Time Stamping Services CA - G2
```

## versions (25)

_SDK and build versions - let us match our emulator to the right Blaze era._

```
0x00ba5a7d  ascii  SDk},
0x00bf5f58  ascii  P:sDK
0x013f36c8  ascii  127.0.0.1
0x01400568  ascii  <?xml version="1.0" encoding="utf-8"?>
0x014b3488  ascii  Build:
0x014e4789  ascii  er un dispositif D3D pour la version: 
0x014e4a80  ascii  "Render.DebugInfoEnable" was also enabled which requires the DirectX SDK to be installed
0x0150ed68  ascii  Wrong JPEG library version: library is %d, caller expects %d
0x01650c40  ascii    ExportInfo: tagType = %d, tool ver = %d.%d, imgfmt = %d, prefix = '%s', swfname = '%s', flags = 0x%X
0x01650cf8  ascii  SWF File version = %d, File length = %d
0x01662ef8  ascii  6.1.0.5
0x01676a60  ascii  <?xml version="1.0" encoding="UTF-8"?>
0x016a6410  ascii  The SDK experienced an internal error.
0x016a6470  ascii  The internal buffer that the SDK is using is not big enough to receive the response. Inform OriginSDK Support.
0x016a68a8  ascii  The core version is too old to work with this SDK version.
0x016a6958  ascii  The IGO could not be loaded, so SDK functionality is degraded.
0x016a69c0  ascii  IGO support is not loaded, so SDK functionality is degraded.
0x016a7118  ascii  1.0.0.16
0x016a9fe8  ascii  &version=
0x0170de25  ascii  Host:239.255.255.250:1900
0x0170ea70  ascii  myIP=%s&myPort=%d&version=1.0&status=%s&gameFeatureID=%s
0x0175ae10  ascii  This PlugIn is currently available for use on the XBox 360 and PS3 (SDK version 240 or later) , Android, and iOS
0x01cee068  utf16  1.4.0.0
0x01d07dc0  ascii  <?xml version='1.0' encoding='UTF-8' standalone='yes'?>
0x01d07f59  ascii        <assemblyIdentity type='win32' name='Microsoft.VC90.CRT' version='9.0.21022.8' processorArchitecture='amd64' publicKeyToken='1fc8b3b9a1e18e3b' />
```

## TDF tag candidates (2784)

_4-character strings [A-Z][A-Z0-9]{3}. Lots of false positives, but real TDF tags look exactly like this._

```
DEST  x8
POST  x3
HEAD  x3
ZZYN  x2
AZFM  x2
V603  x2
SHA1  x2
CUNC  x2
XAQA  x2
DLQA  x2
DWQA  x2
LWQA  x2
TWQA  x2
H2TA  x2
IHDR  x2
IEND  x2
UTES  x2
LQBG  x1
U7F5  x1
MDQ8  x1
HOJ4  x1
JZWK  x1
QARP  x1
ZYYD  x1
EY23  x1
W3S8  x1
I5DV  x1
R0X6  x1
QVY7  x1
FE2X  x1
A9JX  x1
ZQI4  x1
A0HZ  x1
IZRK  x1
R3CE  x1
Z4NE  x1
WCOD  x1
BI7W  x1
ZJXF  x1
KQSL  x1
XYNC  x1
FS68  x1
VFXH  x1
NT7Z  x1
ET54  x1
I628  x1
XCA3  x1
FEA2  x1
NEBE  x1
QYMY  x1
MMUT  x1
TIKP  x1
FJH0  x1
NZKE  x1
B1NB  x1
FY58  x1
K67Z  x1
QQM0  x1
H7X0  x1
K8IF  x1
PSS4  x1
R6QC  x1
F0SN  x1
QV5M  x1
OQGV  x1
RVR8  x1
CH4V  x1
BD5Q  x1
T1I7  x1
Z8KF  x1
S1QV  x1
TNGK  x1
L3UF  x1
RJBZ  x1
S7I8  x1
BS8L  x1
JES5  x1
SHI9  x1
OF13  x1
YAAT  x1
A4JJ  x1
UJC4  x1
VH9M  x1
A2QR  x1
UFZ1  x1
CY77  x1
ZI4P  x1
CUTH  x1
QR21  x1
X86R  x1
UBVC  x1
DNYR  x1
MFI1  x1
DPFA  x1
IQFB  x1
INNS  x1
BFRN  x1
TOHI  x1
EJ1G  x1
G5KM  x1
UTSA  x1
LYNK  x1
PWFH  x1
GTVW  x1
BCM5  x1
PWWN  x1
URDZ  x1
N8N0  x1
LY9N  x1
SB5M  x1
PI92  x1
QDU4  x1
JU9Y  x1
QDRX  x1
DQ3Y  x1
O001  x1
Q4F2  x1
HFA6  x1
V7II  x1
STIP  x1
XXWF  x1
SQBQ  x1
P4OY  x1
Y70Y  x1
QNAU  x1
WBKT  x1
PXJ0  x1
GPK1  x1
COGC  x1
XQII  x1
XB21  x1
TKGB  x1
GE56  x1
A8KU  x1
XD9U  x1
VGSJ  x1
R2NQ  x1
A7WP  x1
WF8T  x1
W14X  x1
LVG3  x1
P8YK  x1
ZPAT  x1
FPW3  x1
AO4L  x1
FJ1Q  x1
BFGI  x1
SEOY  x1
KFVM  x1
Q3ED  x1
L4TP  x1
FBDN  x1
GPVZ  x1
AE2B  x1
N6H4  x1
CV4E  x1
V51Q  x1
ORH6  x1
HF8U  x1
Q3AV  x1
BGY2  x1
R1FV  x1
XZP1  x1
F48W  x1
Z1R1  x1
GNKK  x1
MC6R  x1
C6OA  x1
NA9H  x1
A54W  x1
FQH3  x1
GTD7  x1
GIIA  x1
BIYA  x1
SWN0  x1
AILD  x1
A052  x1
QZT9  x1
YGJX  x1
FMI7  x1
NUAJ  x1
SK92  x1
JDD7  x1
N6H0  x1
LNM6  x1
ULZY  x1
CYKU  x1
AW7P  x1
RK47  x1
U7KJ  x1
V4Z0  x1
WDCC  x1
CT1O  x1
YY5Z  x1
GJOP  x1
L8NS  x1
QEFH  x1
UOE7  x1
WMHG  x1
FOF5  x1
KEH6  x1
CS4X  x1
O767  x1
DA1F  x1
CMMW  x1
K2JA  x1
RTPS  x1
UJ3S  x1
LOJF  x1
ZRFW  x1
BEJ9  x1
S5A0  x1
C0F7  x1
LRVD  x1
CHM0  x1
ZGA4  x1
VDOG  x1
QZPM  x1
R3A4  x1
UU5U  x1
S5ZI  x1
SAO4  x1
MBWB  x1
SF79  x1
UKX4  x1
YJA6  x1
CLXH  x1
KZXU  x1
M0MA  x1
AV9C  x1
N1CN  x1
D7LT  x1
JBJ6  x1
EOUD  x1
WPOY  x1
EM79  x1
NJXG  x1
UJUE  x1
W22W  x1
HHWZ  x1
PW36  x1
ZSWX  x1
KF7T  x1
OKNF  x1
ER61  x1
HVXP  x1
HGW4  x1
AXPF  x1
ZJEA  x1
Y1G2  x1
BTZD  x1
O8Q8  x1
X5FH  x1
HCVO  x1
XR6D  x1
VLMR  x1
MTXQ  x1
IHV5  x1
Z2BC  x1
YE1P  x1
HITU  x1
T8JE  x1
V0LI  x1
V9PW  x1
P6G5  x1
H95R  x1
A7GH  x1
G77Y  x1
FQQY  x1
TTS2  x1
B2D8  x1
IZL8  x1
S6KI  x1
HA1O  x1
Y1KG  x1
TNCG  x1
YS2P  x1
XEWU  x1
P21D  x1
LS77  x1
LD9A  x1
XS93  x1
MIWN  x1
JX2G  x1
IKPT  x1
YLRO  x1
GZBP  x1
MPFH  x1
GEJJ  x1
IKSX  x1
YVE8  x1
TSVN  x1
DYRZ  x1
ENIP  x1
NUVW  x1
C2M4  x1
YOKB  x1
NJIH  x1
GPCQ  x1
SYZ4  x1
BZMY  x1
TK36  x1
T1NG  x1
OOB6  x1
WYFN  x1
Z1M0  x1
N2V9  x1
N07Y  x1
NOVP  x1
B46J  x1
YRV1  x1
RODX  x1
TSG6  x1
GCIW  x1
EJCZ  x1
RSWO  x1
V2KL  x1
WWBI  x1
FPGY  x1
LZNV  x1
PFSD  x1
GN3U  x1
BWCQ  x1
EM92  x1
SLEY  x1
F9OM  x1
P6WG  x1
YLXZ  x1
PPE9  x1
K87H  x1
JQLY  x1
DV34  x1
ZC0Q  x1
K78I  x1
HBYW  x1
YCJR  x1
QDDM  x1
CR3Q  x1
KZM2  x1
RUJS  x1
K7UY  x1
JQJQ  x1
SAAS  x1
UH25  x1
QTDC  x1
XY4C  x1
QBDR  x1
TL8I  x1
OJUG  x1
Q19N  x1
SEXA  x1
ES4C  x1
VYLW  x1
ENS9  x1
CF06  x1
F6CP  x1
VUK0  x1
E1A2  x1
ZXXO  x1
DF08  x1
IWD3  x1
OLY0  x1
SFK1  x1
KCCD  x1
KXLU  x1
B4S1  x1
NLAJ  x1
GH87  x1
ADWM  x1
ODCB  x1
I3LO  x1
RIIP  x1
E4KA  x1
V2UC  x1
MU8B  x1
VNXG  x1
TAZK  x1
E12H  x1
PGMP  x1
M5AR  x1
HPEN  x1
Z987  x1
PBRF  x1
MNJX  x1
COZU  x1
JT6T  x1
RVUF  x1
I2GS  x1
PPKK  x1
AYN3  x1
H5NH  x1
OEBA  x1
Q14D  x1
DOB8  x1
UCNC  x1
G6MR  x1
YOV8  x1
DXTG  x1
GRX3  x1
GCJA  x1
B5S9  x1
ZZ40  x1
TF7D  x1
AMRD  x1
MH9S  x1
EMU6  x1
GTYM  x1
W39I  x1
VPWT  x1
AHDG  x1
YXDU  x1
VMBL  x1
VGHX  x1
M1FE  x1
G17V  x1
RQK8  x1
FE7E  x1
EFHP  x1
FULG  x1
Y9Q2  x1
V327  x1
Q8JO  x1
G45R  x1
R4XW  x1
UTUI  x1
VJRS  x1
NCQM  x1
O25Q  x1
FGIF  x1
W7XF  x1
K9GF  x1
AN80  x1
WPO3  x1
T9G9  x1
G3KS  x1
Q19T  x1
ZI69  x1
UERQ  x1
SVPX  x1
X6TG  x1
GWNT  x1
PX94  x1
T0A8  x1
CE6S  x1
S70Y  x1
ZFWV  x1
FBVX  x1
AK6M  x1
SMSJ  x1
KBGW  x1
AF1U  x1
FCDP  x1
M2VN  x1
UKSE  x1
WLHI  x1
YW6B  x1
X0SG  x1
FZ60  x1
GZO0  x1
VY4M  x1
I9S7  x1
FLVQ  x1
ZEAH  x1
DH6B  x1
OP75  x1
DJU9  x1
IVDJ  x1
O8C8  x1
PDAT  x1
JL1L  x1
TTB9  x1
YE5N  x1
TQL8  x1
M6GW  x1
YD6Q  x1
YDV8  x1
X5WT  x1
QWBU  x1
UT6W  x1
D2HZ  x1
CQYI  x1
KNEA  x1
SLG3  x1
UD3A  x1
NCKV  x1
PU0M  x1
H0XH  x1
ARIH  x1
W3C8  x1
S2XW  x1
EV8J  x1
DEQO  x1
WBXF  x1
B1DO  x1
X9YT  x1
PWL2  x1
QRNC  x1
Z48Y  x1
INTM  x1
WRNW  x1
KGU4  x1
CP5B  x1
PAVI  x1
DQ7D  x1
GQMU  x1
ZQPA  x1
S6L7  x1
ENYQ  x1
ZMVP  x1
ZDZN  x1
BVMA  x1
OSRA  x1
XNCG  x1
QSZA  x1
VYMT  x1
BK2W  x1
L7WO  x1
BCSD  x1
E6EZ  x1
C8U3  x1
YFZ1  x1
DAV3  x1
J8SH  x1
SCFB  x1
RBGJ  x1
UBK4  x1
EYU3  x1
DHBH  x1
LQDD  x1
L1AZ  x1
B0UB  x1
AU09  x1
TY2G  x1
EBIE  x1
BV61  x1
NX34  x1
H4YK  x1
ZYJ3  x1
BP5P  x1
VF9K  x1
UBLA  x1
ACS7  x1
U0Z4  x1
YGS0  x1
YT99  x1
GX1S  x1
NG11  x1
CWG5  x1
NP8Z  x1
FR09  x1
O64D  x1
NDE4  x1
GGCQ  x1
DRB6  x1
GOTE  x1
CEBY  x1
CZFR  x1
S772  x1
I83B  x1
NSLU  x1
WP97  x1
S541  x1
FNJ2  x1
EZ2G  x1
IXO3  x1
UJ3B  x1
C33Q  x1
QA8D  x1
QGAP  x1
N5R9  x1
ME5R  x1
EUNS  x1
EALV  x1
GB8H  x1
YY7K  x1
ROPC  x1
TRID  x1
SXVL  x1
ZGST  x1
DVXU  x1
PRWN  x1
HX4T  x1
QS74  x1
L2JW  x1
VTS8  x1
CL15  x1
XYK3  x1
F7Q6  x1
UBPD  x1
KFHK  x1
IIAG  x1
G4AD  x1
UC35  x1
ND4K  x1
ZQ9W  x1
X6GV  x1
M27O  x1
COO9  x1
YQLI  x1
MRX6  x1
ZR09  x1
FAHA  x1
XJHX  x1
UTBD  x1
IZ2J  x1
PWWL  x1
BEZN  x1
TLV2  x1
KN2O  x1
UPSC  x1
XJMS  x1
YWUY  x1
LHN3  x1
D6NP  x1
GF6R  x1
NPZ0  x1
WAGX  x1
JD8R  x1
IHC9  x1
FBJK  x1
XRVS  x1
L8BJ  x1
PTUJ  x1
HR8K  x1
VARQ  x1
LEOD  x1
NIJ4  x1
GLDD  x1
C42Q  x1
NSVS  x1
IAWB  x1
Y2TA  x1
CP1S  x1
SMJZ  x1
SSUP  x1
ALUP  x1
A8R9  x1
I67V  x1
QCH2  x1
Q80G  x1
ZXC3  x1
S3MN  x1
JT0L  x1
A48P  x1
IOFC  x1
YU2M  x1
UORS  x1
RT7O  x1
A52Q  x1
XVJ7  x1
K8KK  x1
MPA1  x1
Y7P0  x1
I9UL  x1
TD5D  x1
KOO5  x1
HEFW  x1
FKCE  x1
Y9LB  x1
VB1M  x1
D8Y0  x1
MT8E  x1
WFGP  x1
MJWQ  x1
W6ZA  x1
XBCD  x1
GX36  x1
LNBH  x1
EF9T  x1
ARS7  x1
G81J  x1
PLSN  x1
F1QN  x1
XYAM  x1
HMSY  x1
UNUX  x1
KOBJ  x1
BZ0A  x1
HAOC  x1
HU4P  x1
SPVG  x1
YTPP  x1
KA83  x1
PEYE  x1
Z91W  x1
EOQE  x1
QWDT  x1
GN97  x1
QUXJ  x1
MKQM  x1
ZUP6  x1
V6DB  x1
VT4L  x1
BFD5  x1
UM9X  x1
W0NT  x1
DDY9  x1
EATL  x1
EMFW  x1
NFI4  x1
TNA3  x1
JCIV  x1
LIS3  x1
Y5I9  x1
ZAJF  x1
QLLO  x1
ICNS  x1
SLTG  x1
JXH6  x1
MJ2G  x1
MWUB  x1
EHQ9  x1
W0BW  x1
TP2P  x1
DVXW  x1
L2IZ  x1
OSBK  x1
ATAC  x1
JICG  x1
JI1R  x1
QGU1  x1
W936  x1
MXN6  x1
U46X  x1
T94M  x1
YPLI  x1
XT0U  x1
U9SP  x1
VKUZ  x1
FC5B  x1
JG7Z  x1
UL5K  x1
NWIL  x1
MA2V  x1
BN65  x1
WZNR  x1
PGT1  x1
D64L  x1
MBUB  x1
F242  x1
LLLS  x1
VD7O  x1
CCXW  x1
RHQT  x1
HKXG  x1
ZIRB  x1
N73O  x1
APFG  x1
FU38  x1
UYNB  x1
ALBZ  x1
IDZL  x1
UJ2E  x1
UMRT  x1
I70A  x1
ZN1H  x1
KRII  x1
U7XZ  x1
U757  x1
NLTV  x1
IJL7  x1
RHL1  x1
VBV7  x1
RSP5  x1
VCKV  x1
VN93  x1
DO7A  x1
V41Y  x1
LV4J  x1
T75C  x1
HJRY  x1
K8DE  x1
LWMQ  x1
KIIN  x1
FKSJ  x1
Y8LY  x1
KL3U  x1
P2PH  x1
W0E1  x1
IPD0  x1
BGM2  x1
FYZS  x1
AQH2  x1
Y2CA  x1
FIMB  x1
RF29  x1
G5SY  x1
CWNM  x1
B0Z3  x1
AYRJ  x1
PTMJ  x1
JF7Z  x1
TU7K  x1
OOLW  x1
RJMH  x1
SHPG  x1
GCQ5  x1
F35R  x1
RJAX  x1
N7MG  x1
FYRU  x1
WE83  x1
MYZ7  x1
SDHR  x1
OW7G  x1
KTCI  x1
EX83  x1
V0AI  x1
SLZ6  x1
OXSJ  x1
U2BZ  x1
F3EP  x1
I1S7  x1
V2AQ  x1
YKUE  x1
X83N  x1
BCAS  x1
SZHC  x1
G92T  x1
N6O0  x1
FRET  x1
VLDB  x1
ZV9M  x1
BC3J  x1
VHV7  x1
S8DA  x1
QIO3  x1
YCTP  x1
MBZW  x1
NAMG  x1
QJZ6  x1
ILGG  x1
IVNO  x1
EYJV  x1
CSV2  x1
YK4O  x1
IRSU  x1
ONME  x1
JE8Q  x1
VMTT  x1
GN6G  x1
H8WN  x1
B496  x1
BPGM  x1
NKB9  x1
OOYA  x1
KM3P  x1
YSNB  x1
B88L  x1
IO9S  x1
DIG3  x1
INVZ  x1
QXRX  x1
W01Z  x1
QO3X  x1
J8UC  x1
LBVD  x1
AGK4  x1
XJB0  x1
N2M2  x1
CPJV  x1
T16W  x1
XIYI  x1
VMN8  x1
WZ2M  x1
FG38  x1
Z86P  x1
KRTY  x1
ULBE  x1
F81U  x1
JV4X  x1
UHFL  x1
NEIE  x1
Z77M  x1
R5D1  x1
CZWX  x1
JCY5  x1
RFJA  x1
VNL4  x1
M8GL  x1
DWVS  x1
JU5E  x1
I1ZL  x1
HYS7  x1
FQ18  x1
FVEA  x1
XSZW  x1
QLEW  x1
YGDD  x1
V9J0  x1
FZE4  x1
QP81  x1
Z5ZU  x1
MFH0  x1
N6S6  x1
J1EB  x1
B8ZX  x1
V07V  x1
CSO2  x1
TVSM  x1
JZ48  x1
IKPF  x1
YYC3  x1
PFTZ  x1
F607  x1
O0N6  x1
WRM6  x1
ILCQ  x1
AL5O  x1
V6GS  x1
U2BP  x1
DW69  x1
EBFF  x1
TF8U  x1
LVDN  x1
QSPV  x1
KXPE  x1
LG6H  x1
IKHD  x1
CMOL  x1
IC6C  x1
GGPI  x1
P89J  x1
DXQA  x1
BKDX  x1
LQMR  x1
IYOR  x1
J20I  x1
LXU5  x1
NPXP  x1
BZI1  x1
RU3S  x1
NO2D  x1
AZJI  x1
TJ4U  x1
D1HF  x1
YQ8S  x1
K56H  x1
DIGR  x1
RFJB  x1
SOHP  x1
LRR8  x1
KVXL  x1
PI9K  x1
EW8Z  x1
AWHS  x1
GIKV  x1
FSMX  x1
TWDB  x1
LNYW  x1
RGCB  x1
NVN3  x1
B18R  x1
PMYM  x1
JQ0V  x1
QFQV  x1
U0CR  x1
MXKY  x1
B3X4  x1
JHT7  x1
IPY6  x1
WPRN  x1
QLGN  x1
GDQ5  x1
LSW7  x1
W16N  x1
XRGO  x1
IPWA  x1
RYBA  x1
E52I  x1
XRLE  x1
MP5K  x1
HJKX  x1
TKG2  x1
FJ91  x1
ZQ2X  x1
H64J  x1
HSY3  x1
TYNG  x1
K1B1  x1
O5S9  x1
PW8P  x1
Q3RE  x1
JK66  x1
A6MY  x1
J9HB  x1
C2JI  x1
VW9O  x1
B42Q  x1
FZGW  x1
OS79  x1
U5VP  x1
KH3E  x1
XOW2  x1
MAN8  x1
D7FZ  x1
A40X  x1
QI2R  x1
Y2WH  x1
WW91  x1
WS28  x1
YI2C  x1
PC9G  x1
EE44  x1
Z8GM  x1
P02M  x1
V942  x1
UANR  x1
WUEP  x1
G6XY  x1
H2M0  x1
YEV0  x1
OE0F  x1
KS4O  x1
TMDO  x1
GTO8  x1
HL4Q  x1
S29E  x1
PEBL  x1
U0A9  x1
P079  x1
DM9K  x1
S22J  x1
RG97  x1
AJD2  x1
BUDI  x1
Q0Y5  x1
TDQ7  x1
EDLI  x1
ZPY5  x1
YGMO  x1
TP36  x1
VP52  x1
HZSB  x1
OOU1  x1
HLWB  x1
R2DT  x1
QPOI  x1
YM9O  x1
JJNW  x1
ODYK  x1
AD04  x1
BW7R  x1
AY8E  x1
CJV6  x1
IUKK  x1
D96F  x1
Z0NP  x1
ZPX3  x1
CQ65  x1
X0BG  x1
N2MJ  x1
NE1U  x1
UK0R  x1
LVAG  x1
F9YN  x1
X8IF  x1
NLIT  x1
BNOI  x1
OXPS  x1
WIZR  x1
PYOW  x1
VI8J  x1
GNPQ  x1
ISFO  x1
HWY9  x1
JCJP  x1
D0KN  x1
WHPU  x1
K648  x1
PBQ3  x1
LBMP  x1
VNA2  x1
X472  x1
CAC3  x1
KNT0  x1
KNL8  x1
BIH9  x1
IP9Q  x1
NW6P  x1
R0PH  x1
W481  x1
O5BE  x1
DTWN  x1
W4UQ  x1
DYKV  x1
TC8L  x1
HMFG  x1
N1JH  x1
M6GJ  x1
N8TL  x1
K8HU  x1
OU3T  x1
ISHO  x1
JZAK  x1
JJ1I  x1
HO0F  x1
CC53  x1
F6WO  x1
XA8R  x1
CEWA  x1
VGYW  x1
XJFW  x1
O7V0  x1
RP7M  x1
HWTI  x1
NQXE  x1
OZ8Z  x1
H6UU  x1
MKVC  x1
GIRS  x1
XXHD  x1
J1GB  x1
K8YZ  x1
CHJF  x1
IQ4P  x1
EBTF  x1
CYT3  x1
R8HM  x1
IZYU  x1
KD85  x1
EX2S  x1
E2YA  x1
HG3E  x1
GKT0  x1
S4CE  x1
AK8K  x1
VILP  x1
XFML  x1
N6L8  x1
MBZ5  x1
X7R5  x1
RRML  x1
EKPT  x1
H5L8  x1
H2RR  x1
T7AM  x1
L1Y7  x1
QIQT  x1
A0K0  x1
CZPK  x1
B5B1  x1
VAY2  x1
HT47  x1
AZJ5  x1
KQHR  x1
T5PN  x1
VUXN  x1
NS88  x1
FWFO  x1
GOZ5  x1
NX2S  x1
PYOY  x1
K33H  x1
Z53J  x1
NV0Y  x1
FVA6  x1
Y6QK  x1
I13I  x1
ZK71  x1
DOXW  x1
SPDL  x1
PZ74  x1
BD4T  x1
B21H  x1
D1T7  x1
QT0S  x1
LIXP  x1
X21O  x1
FCVZ  x1
H300  x1
Y3N1  x1
TA6P  x1
ZDTH  x1
GUHQ  x1
M9Z6  x1
MTC8  x1
SCVK  x1
QXJV  x1
W1EE  x1
VJ1E  x1
A33W  x1
ER2P  x1
KO2G  x1
KHT8  x1
BAYA  x1
RDWB  x1
CMN1  x1
QWYJ  x1
BJ6B  x1
XUZI  x1
SRV7  x1
UISI  x1
V0A5  x1
PPS6  x1
BK6Z  x1
TU6K  x1
MRHC  x1
UZHR  x1
ERMR  x1
QJ13  x1
RFD8  x1
CS8N  x1
MU2U  x1
PV00  x1
DLN2  x1
UO7D  x1
EOUB  x1
LXH1  x1
FE42  x1
QQN6  x1
ZX8I  x1
OGLF  x1
VM1I  x1
RATH  x1
WXSU  x1
R2LF  x1
TQ6I  x1
R331  x1
IJ6B  x1
LDSF  x1
ETCA  x1
YZ7M  x1
H7LV  x1
R4A3  x1
NS7E  x1
KUNK  x1
O4ND  x1
REZC  x1
A9XT  x1
SBF4  x1
DJ1W  x1
S79Q  x1
QPNO  x1
PMJP  x1
OQ8I  x1
CS7T  x1
X3H6  x1
P4AF  x1
M6JC  x1
R994  x1
KRHC  x1
VZ5T  x1
ELBD  x1
Y3L3  x1
FUJ7  x1
TTI1  x1
DRV9  x1
YCMA  x1
U7VV  x1
S3XB  x1
QU3C  x1
PV0B  x1
ZTEI  x1
MO9P  x1
JOLU  x1
ZLMJ  x1
MUGJ  x1
IUYQ  x1
FJ5Q  x1
EXLH  x1
OUS9  x1
KWHP  x1
FIEQ  x1
X60F  x1
JJUX  x1
CV4T  x1
K6VQ  x1
DK0Y  x1
FF49  x1
UG8W  x1
A6QA  x1
K652  x1
Z6RM  x1
NCZN  x1
LZZM  x1
TZ58  x1
EAAP  x1
XCF6  x1
SKO4  x1
PT51  x1
U26U  x1
UPWM  x1
BO72  x1
LJU2  x1
U90V  x1
LKGL  x1
XHBE  x1
VWCL  x1
M6NZ  x1
AN2I  x1
Q6DZ  x1
FSZJ  x1
E46W  x1
B59X  x1
VWA3  x1
TCPN  x1
XYE0  x1
GRW0  x1
E89E  x1
DA77  x1
HUCN  x1
UNUT  x1
B70N  x1
M9JH  x1
ATHO  x1
PFBH  x1
D4U4  x1
TZMX  x1
EEHV  x1
SAF0  x1
UFFR  x1
SAUG  x1
KNQJ  x1
ZSEP  x1
B02E  x1
O6NS  x1
SH4Y  x1
ELPE  x1
ATYF  x1
LKYW  x1
LNPZ  x1
X561  x1
T3A4  x1
MXCQ  x1
POER  x1
XEX1  x1
JTXO  x1
FZDO  x1
DWNS  x1
JQHK  x1
IBOF  x1
ZVQN  x1
YPUH  x1
N2L0  x1
Q1GV  x1
XWVQ  x1
C100  x1
QNJO  x1
PDGT  x1
E6FY  x1
LIBT  x1
ESIP  x1
GA55  x1
Q0GJ  x1
VHD8  x1
P9JR  x1
NOGT  x1
RCIU  x1
L0MU  x1
URPN  x1
EB7X  x1
XMGX  x1
CMZ1  x1
SNTB  x1
XBRM  x1
O2NB  x1
PR36  x1
B3XD  x1
ERSH  x1
IRXM  x1
ACD5  x1
TJ9X  x1
PB1D  x1
K8XY  x1
KDIP  x1
W3E1  x1
EKXR  x1
MVWU  x1
E9AA  x1
ZSI2  x1
P2QL  x1
CPX7  x1
KIS1  x1
JTJ3  x1
QTMX  x1
GYKJ  x1
ETUX  x1
CC93  x1
GVAF  x1
YF28  x1
Y15A  x1
I45P  x1
TF9F  x1
J73R  x1
PO2E  x1
JQ3B  x1
BMO8  x1
ET59  x1
U2B1  x1
ELTB  x1
G2PT  x1
GJQ2  x1
SX9M  x1
IFHV  x1
ZI1D  x1
L0MH  x1
KOVB  x1
S7K6  x1
KD7N  x1
TF1Q  x1
LI7U  x1
W364  x1
JNO2  x1
Q47T  x1
JBAC  x1
FWG5  x1
YTDB  x1
L341  x1
TYMU  x1
CCB3  x1
CM3L  x1
MJXX  x1
UTO0  x1
HPAN  x1
N5PN  x1
ZBAS  x1
KFCO  x1
CW3T  x1
UH3Z  x1
YOJ6  x1
ODMM  x1
SR57  x1
LJSK  x1
SUA2  x1
X3KM  x1
OA99  x1
V500  x1
Y98Y  x1
D962  x1
JBPJ  x1
G108  x1
I0KA  x1
ZI02  x1
CSVB  x1
X2RQ  x1
KSZS  x1
IZ3W  x1
ROOW  x1
VL1O  x1
KETQ  x1
U9RV  x1
WPUE  x1
C2JM  x1
TM0W  x1
M8FG  x1
D791  x1
P016  x1
SNYN  x1
AM8R  x1
WHQG  x1
GG9G  x1
HW0S  x1
R0VZ  x1
NHZN  x1
HCMI  x1
H31D  x1
HBPH  x1
ED3W  x1
QH6O  x1
TNQP  x1
WIPW  x1
WMBW  x1
P6PS  x1
QH4D  x1
FK0S  x1
BU4F  x1
QENV  x1
PW9C  x1
KVMO  x1
SNSS  x1
R2HY  x1
NT0G  x1
Q8BV  x1
RU62  x1
NS8S  x1
BYHV  x1
WEWW  x1
O199  x1
H7DA  x1
W4CQ  x1
PKNW  x1
OX0F  x1
HFHN  x1
D2U4  x1
GLSJ  x1
HOCS  x1
W36Z  x1
TNP3  x1
DRIR  x1
CKDX  x1
ED6U  x1
ZY36  x1
FMF3  x1
OK8Z  x1
SOA7  x1
Q0JL  x1
W1TR  x1
KH0Z  x1
BRYL  x1
HJXC  x1
Q0M0  x1
TMPU  x1
KW96  x1
G1MS  x1
Y722  x1
K5BW  x1
EPYT  x1
WFZZ  x1
OEYR  x1
LJQW  x1
O568  x1
W57R  x1
J87V  x1
ESAD  x1
HNMZ  x1
RCW5  x1
Q7RA  x1
GVIR  x1
EK20  x1
IVGK  x1
KFUY  x1
IODS  x1
QC8Y  x1
YMA4  x1
YK5X  x1
Y4Y9  x1
WEAC  x1
Z8N9  x1
M6Q8  x1
JP2K  x1
OSFV  x1
WHY6  x1
AHAA  x1
FFMY  x1
WCM5  x1
RFT5  x1
YE1E  x1
TWW1  x1
ERVO  x1
C05I  x1
FT6D  x1
USDV  x1
PNT4  x1
IR0D  x1
WZXK  x1
ZUPM  x1
JF4D  x1
YHO2  x1
K6S0  x1
N9FH  x1
GL2W  x1
IR6K  x1
RCHM  x1
ATT9  x1
A25O  x1
SVLI  x1
E9IT  x1
FQTB  x1
JCCZ  x1
KK14  x1
EQJM  x1
NTK2  x1
IVEM  x1
DH5S  x1
JXLK  x1
CUJP  x1
ZVUR  x1
VKYR  x1
YQ8R  x1
LX8R  x1
UYXA  x1
JFUS  x1
IU3V  x1
L6HQ  x1
RXZE  x1
WQO3  x1
EU9S  x1
AU6E  x1
CHH2  x1
XFHP  x1
EBOT  x1
RPFP  x1
E0OQ  x1
NK97  x1
QQQ3  x1
KXP8  x1
W45B  x1
HSUH  x1
RZWQ  x1
PLCK  x1
C3N7  x1
KXTY  x1
QZWX  x1
HFKN  x1
FGSC  x1
KNFJ  x1
IV13  x1
TBJE  x1
QJK7  x1
VM7A  x1
NXKJ  x1
UXBK  x1
NQ92  x1
SWAE  x1
FT35  x1
M5ID  x1
L5DO  x1
S8ZX  x1
FDSR  x1
M4BY  x1
AO7P  x1
PNG9  x1
R575  x1
YVG4  x1
NFGY  x1
V01C  x1
O924  x1
UBP9  x1
JZR3  x1
HHQI  x1
SVW5  x1
GROL  x1
MOS7  x1
XBE9  x1
SU3U  x1
FU34  x1
BNXE  x1
UHK7  x1
SQ2J  x1
NXHD  x1
NU3R  x1
LWQB  x1
VUT2  x1
S84J  x1
G454  x1
E4AV  x1
M0OX  x1
CCYE  x1
GKFX  x1
FGIB  x1
EY17  x1
ZCJY  x1
FLV7  x1
BFFW  x1
BN29  x1
FBLB  x1
F6RJ  x1
HGI5  x1
N31F  x1
JXM6  x1
GYC2  x1
LSOW  x1
LLYK  x1
OYRJ  x1
ZZLM  x1
GWJW  x1
S9CH  x1
OAB2  x1
HFOT  x1
YK73  x1
O7US  x1
I99B  x1
M6OG  x1
WQFQ  x1
GUZJ  x1
W2UW  x1
ZSUB  x1
FGOP  x1
YTT1  x1
ENH2  x1
F5U7  x1
OKVN  x1
O00O  x1
N3JK  x1
AAL4  x1
RTE3  x1
T57P  x1
TF9G  x1
HXHI  x1
V177  x1
NN27  x1
A8RT  x1
L6VP  x1
JKPQ  x1
XPNE  x1
BUET  x1
JOVX  x1
O7G9  x1
XZTG  x1
KMIF  x1
B2QP  x1
OFHJ  x1
V1PA  x1
WWCV  x1
OQE7  x1
TA6K  x1
BTEU  x1
P9FO  x1
XD1T  x1
Y0WC  x1
E06S  x1
DY7O  x1
MEMN  x1
AYOL  x1
T7JS  x1
IVTR  x1
R5JL  x1
JNI2  x1
Y272  x1
P3GA  x1
ZZH1  x1
JUSG  x1
F57S  x1
O0X0  x1
D12H  x1
N2XT  x1
IPKX  x1
T96V  x1
PNR7  x1
EGJH  x1
U26B  x1
RVZ1  x1
LVD7  x1
AD2S  x1
X4A9  x1
V0A9  x1
ZTEF  x1
CSMD  x1
I682  x1
MFOV  x1
EKF7  x1
N6GW  x1
KARH  x1
TRYN  x1
N1YB  x1
IHZ2  x1
VS4F  x1
TYXP  x1
GVN8  x1
NX16  x1
CTI3  x1
LYQG  x1
M38X  x1
OU23  x1
JV3B  x1
FQBZ  x1
DY86  x1
LEIH  x1
U9J0  x1
RHV5  x1
EFES  x1
QFFU  x1
ZXFY  x1
ZMML  x1
Y7TP  x1
DNEM  x1
CAAB  x1
PFTQ  x1
NTPK  x1
GM34  x1
HVT1  x1
R4DJ  x1
FTRU  x1
T064  x1
ZQ2R  x1
LPTT  x1
X71D  x1
RHD0  x1
YFS2  x1
U3ID  x1
XIPW  x1
G1UK  x1
FP9F  x1
UFCO  x1
WK5N  x1
U2XT  x1
ACCI  x1
WWOT  x1
AD48  x1
FNSA  x1
HJGI  x1
IVPN  x1
JZNP  x1
P12D  x1
QLGP  x1
P20T  x1
STCR  x1
L03N  x1
XJ9D  x1
E087  x1
AOXQ  x1
KGUT  x1
R0CT  x1
ITA1  x1
TVFE  x1
XS7S  x1
A4KE  x1
R4C1  x1
YLF6  x1
J6K9  x1
Y7JA  x1
N9AB  x1
IS5H  x1
DXZ3  x1
A6MR  x1
TT0P  x1
YP21  x1
A4JC  x1
WE1W  x1
HZA2  x1
I2UL  x1
BR5S  x1
R1Y3  x1
SJI8  x1
Z0NA  x1
WRZS  x1
ZDMI  x1
HOQI  x1
GOD2  x1
P0DP  x1
L7YE  x1
NMIC  x1
G8BA  x1
Y31K  x1
EPJ7  x1
UPSH  x1
WBJV  x1
YEYW  x1
NXIF  x1
FUER  x1
W44J  x1
KMTO  x1
DC9R  x1
F2CD  x1
C12P  x1
YPD1  x1
N3KG  x1
KLIU  x1
P2VW  x1
V1JI  x1
KXXM  x1
H1SC  x1
RGXY  x1
LK0A  x1
IV1O  x1
JV5E  x1
TPX9  x1
KNK0  x1
H2TJ  x1
D5U0  x1
V4NF  x1
I5B3  x1
CX02  x1
D7J1  x1
KMH9  x1
V3DL  x1
L7G1  x1
CFJI  x1
ZL4Z  x1
H9ZV  x1
CZS8  x1
Y4UG  x1
DKVM  x1
I6WI  x1
H9PH  x1
XS2Z  x1
TPAO  x1
WJN5  x1
DJF6  x1
DIND  x1
DV6T  x1
U5YI  x1
JL85  x1
Q50Z  x1
Q5IL  x1
XLKY  x1
R0M5  x1
QX20  x1
TIPR  x1
Q7LX  x1
W279  x1
WHA4  x1
D8QM  x1
MKKX  x1
CRR2  x1
XCH1  x1
JXHL  x1
H1E8  x1
KG8U  x1
IO13  x1
MMVY  x1
EVNH  x1
L6L8  x1
XRRN  x1
QJB6  x1
UKUO  x1
P7GB  x1
EO0E  x1
XUZN  x1
OSQI  x1
IUKU  x1
DJUO  x1
MX82  x1
ZT5B  x1
H1LA  x1
GBCF  x1
C89X  x1
CFG8  x1
ZN1S  x1
J3CU  x1
MQED  x1
WIQU  x1
EE8A  x1
X4SM  x1
W7B6  x1
VASD  x1
TKLS  x1
KYIE  x1
GG8P  x1
ZMS8  x1
ZYHK  x1
JF26  x1
C08J  x1
JGHU  x1
K796  x1
FR2N  x1
O41B  x1
GEQR  x1
F03J  x1
SZHO  x1
W3KF  x1
OBU8  x1
XFT6  x1
D55L  x1
MWD1  x1
Q6M4  x1
NWRW  x1
FGV4  x1
QJ9W  x1
E9F1  x1
LG37  x1
VDR0  x1
XZ21  x1
WSYK  x1
E5V1  x1
O3C7  x1
ISF3  x1
SJDL  x1
PUQN  x1
B00I  x1
EMS1  x1
MWUG  x1
FXJC  x1
LDLX  x1
HP4G  x1
JXGA  x1
WWNJ  x1
DE2B  x1
DL5H  x1
JMAY  x1
SZ82  x1
GUUE  x1
P8VR  x1
TW1Y  x1
W3YR  x1
N1VF  x1
JOSN  x1
N6P3  x1
B3VE  x1
ORLI  x1
U5XS  x1
CYOM  x1
EZFO  x1
TFTM  x1
OWS4  x1
IHA3  x1
KRNV  x1
HV9J  x1
UJ2H  x1
XZ1G  x1
JIHV  x1
J9XB  x1
SPSR  x1
V8VP  x1
WFNH  x1
VD1E  x1
DF0Z  x1
KO7N  x1
FGS8  x1
FXGG  x1
BYWB  x1
VMXN  x1
BQNF  x1
DQKZ  x1
LK23  x1
TPV1  x1
M0FH  x1
FECD  x1
LAY5  x1
Q9N0  x1
R0WW  x1
ENPR  x1
L36C  x1
JPOS  x1
NKKI  x1
L7PG  x1
IDEQ  x1
BRHD  x1
IJG4  x1
DAC3  x1
A3DL  x1
UHSK  x1
FO83  x1
A4TO  x1
Q3DU  x1
GIUH  x1
WM16  x1
NP02  x1
IY8C  x1
TYE0  x1
OLDO  x1
IYH5  x1
MZRN  x1
L6RP  x1
K0MX  x1
XS8D  x1
AZNO  x1
X8OH  x1
DO0F  x1
IOON  x1
DKOY  x1
UIND  x1
LY7P  x1
U7ZQ  x1
GZYV  x1
AX3P  x1
RRWE  x1
F71Z  x1
ZQTF  x1
NOAK  x1
GCBA  x1
EQQN  x1
ZRWM  x1
MDF7  x1
WHT0  x1
QLNR  x1
FMN5  x1
N1CY  x1
YMRA  x1
A1AX  x1
P8KN  x1
Z7MR  x1
L28H  x1
CGFB  x1
TXIH  x1
F7XP  x1
IBFS  x1
UAGE  x1
D1IV  x1
FOF8  x1
H78J  x1
TAOC  x1
LY8P  x1
RLXR  x1
N2C2  x1
YKU0  x1
VE9G  x1
E4OJ  x1
YQ6X  x1
S6NX  x1
Y741  x1
TANH  x1
L08Y  x1
V1I0  x1
D7EO  x1
GCLQ  x1
ZJEG  x1
R7FE  x1
U22R  x1
AIGC  x1
WWYO  x1
Y8TT  x1
ENED  x1
X4D1  x1
C0GH  x1
BU8X  x1
PKY7  x1
ISS9  x1
HZK1  x1
FKDR  x1
A70M  x1
TDXW  x1
ZE1K  x1
NKJA  x1
V2XZ  x1
R8NW  x1
VYAI  x1
RSR0  x1
GSGL  x1
NRJ5  x1
GA8O  x1
OE45  x1
C6DD  x1
OSD5  x1
BNTQ  x1
MWQL  x1
XE5K  x1
I7MX  x1
XKXJ  x1
EXJN  x1
DAKR  x1
U2AH  x1
W87W  x1
AQ16  x1
MXGK  x1
Y2XY  x1
RWFC  x1
QDOK  x1
KP87  x1
VKEN  x1
L9JG  x1
JAP2  x1
H28A  x1
MIRC  x1
GAXT  x1
CLO9  x1
N4UF  x1
V94S  x1
X12P  x1
BA04  x1
FV9W  x1
ONNR  x1
MZPP  x1
VLQJ  x1
EZMV  x1
NGM3  x1
S7W1  x1
M0UU  x1
BI46  x1
YVBE  x1
D3AF  x1
B3WP  x1
KPKI  x1
YGPI  x1
KMHH  x1
W8TB  x1
N4K3  x1
M6BV  x1
QOUC  x1
SYOJ  x1
IQ4Q  x1
P8E5  x1
KH00  x1
O7F8  x1
WV8U  x1
LBHB  x1
RO3R  x1
ZH7U  x1
DGYM  x1
PNFM  x1
BAPJ  x1
WMGA  x1
DAHH  x1
WHFN  x1
COTT  x1
J0PK  x1
SENY  x1
BDIJ  x1
SI41  x1
BJUR  x1
U1RS  x1
LLL2  x1
EHD6  x1
SCU4  x1
G8ZM  x1
NSI0  x1
QPB7  x1
R7G9  x1
DJDW  x1
KSL1  x1
RLEJ  x1
VG9O  x1
WYAZ  x1
L72A  x1
OXS8  x1
VM4W  x1
MTJ6  x1
C1NG  x1
BQQ3  x1
C80B  x1
QUHB  x1
P2TN  x1
OU0W  x1
ZYNQ  x1
LCWB  x1
WUBI  x1
CS1A  x1
HSY4  x1
DOBM  x1
N0KC  x1
A8SE  x1
JTYE  x1
JUTF  x1
NKJ6  x1
UFY7  x1
THUP  x1
LT6F  x1
O9LY  x1
H4GY  x1
YWYE  x1
ANTI  x1
DWD0  x1
U59K  x1
PSTG  x1
ZB5U  x1
XTDN  x1
XBH5  x1
EOR7  x1
EBR9  x1
TWZJ  x1
MF7V  x1
HLJD  x1
DN66  x1
KIB6  x1
HTM0  x1
JXKV  x1
I67O  x1
ERWE  x1
R7SM  x1
IRQ2  x1
P6YJ  x1
NKVA  x1
XI94  x1
QE73  x1
CBKH  x1
X2VB  x1
NDAV  x1
P6SD  x1
DY8O  x1
VPFQ  x1
ON1V  x1
GB3X  x1
LFB1  x1
MCYY  x1
ZPKW  x1
BIK1  x1
OZ84  x1
D1NS  x1
WYWX  x1
NOM1  x1
OFU5  x1
B6AX  x1
PDPY  x1
R8CB  x1
WG3L  x1
CHKP  x1
L7IP  x1
NKXR  x1
BCV3  x1
U7NA  x1
XSG5  x1
B1RL  x1
HLRE  x1
L1Z5  x1
GGIT  x1
OXCD  x1
HOLY  x1
PJTX  x1
XC8C  x1
W1GJ  x1
FRG0  x1
FGI9  x1
P00A  x1
P91A  x1
P01A  x1
P81A  x1
P31A  x1
PB2A  x1
PK2A  x1
PE2A  x1
PI2A  x1
PL3A  x1
PO3A  x1
PU3A  x1
PX3A  x1
PR3A  x1
P44A  x1
PF4A  x1
P74A  x1
P75A  x1
P35A  x1
P45A  x1
P05A  x1
PP5A  x1
PG5A  x1
PM5A  x1
PJ5A  x1
PD5A  x1
P16A  x1
P36A  x1
PC6A  x1
PF6A  x1
PT6A  x1
PW6A  x1
PD7A  x1
PA7A  x1
PY7A  x1
PV7A  x1
P38A  x1
P68A  x1
PO8A  x1
PU8A  x1
PV8A  x1
PX8A  x1
PR8A  x1
PO9A  x1
PL9A  x1
PR9A  x1
PU9A  x1
PC9A  x1
PI9A  x1
PF9A  x1
PX9A  x1
EDIT  x1
NULL  x1
TRUE  x1
GUID  x1
RSA1  x1
ATAI  x1
ST00  x1
P70A  x1
P60A  x1
QHZ2  x1
QHZ3  x1
QHZ4  x1
SSZ1  x1
SSZ2  x1
SSZ3  x1
SSZ4  x1
QTZ1  x1
LFZO  x1
LMUX  x1
LMUY  x1
LGAY  x1
LRES  x1
LGAZ  x1
LXAL  x1
LYKA  x1
LGYR  x1
LGAX  x1
PCX1  x1
PDX1  x1
PDX2  x1
PDX3  x1
PEX1  x1
PEX2  x1
PEX3  x1
PEX4  x1
PKX1  x1
PKX2  x1
PKX3  x1
PHX1  x1
PHX2  x1
PVX1  x1
PVX2  x1
RBX1  x1
RBX2  x1
RCX1  x1
RHX1  x1
PTX1  x1
PTX2  x1
PTX3  x1
REX1  x1
REX2  x1
QSX1  x1
QSX2  x1
QSX3  x1
PCY1  x1
PDY1  x1
PDY2  x1
PDY3  x1
PEY1  x1
PEY2  x1
PEY3  x1
PEY4  x1
PKY1  x1
PKY2  x1
PKY3  x1
PHY1  x1
PHY2  x1
PHY3  x1
PVY1  x1
PVY2  x1
PVY3  x1
PVY4  x1
RBY1  x1
RBY2  x1
RBY3  x1
RCY1  x1
RHY1  x1
RVY1  x1
RVY2  x1
RVY3  x1
RVY4  x1
RVY5  x1
RVY6  x1
PTY1  x1
PTY2  x1
REY1  x1
REY2  x1
RHY2  x1
QSY1  x1
QSY2  x1
QBZ1  x1
QBZ2  x1
QBZ3  x1
QBZ4  x1
QBZ5  x1
QBZ9  x1
QCZ1  x1
QDZ1  x1
QDZ2  x1
QDZ3  x1
QDZ4  x1
QDZ6  x1
QDZ7  x1
QDZ8  x1
QDZ9  x1
QEZ1  x1
QEZ2  x1
QEZ3  x1
QEZ4  x1
QEZ5  x1
QHZ1  x1
G45Y  x1
PP2A  x1
PS2A  x1
PT2A  x1
PJ3A  x1
IDAT  x1
XBQA  x1
LHQA  x1
THQA  x1
MOVE  x1
SELF  x1
TEST  x1
CALL  x1
H0TA  x1
FRST  x1
SIGN  x1
GAME  x1
ONLI  x1
BLGM  x1
STAM  x1
GMAP  x1
USRM  x1
MMAK  x1
GMSS  x1
STRT  x1
SESS  x1
BOOT  x1
SELE  x1
LANG  x1
ENDS  x1
NORM  x1
MILE  x1
GPRG  x1
TLM3  x1
RCTR  x1
ATLG  x1
RCCM  x1
PLTE  x1
QRVW  x1
FRAD  x1
FRRF  x1
FREX  x1
PX4A  x1
PQ4A  x1
PW4A  x1
PA5A  x1
PW5A  x1
PV5A  x1
PP6A  x1
PL6A  x1
PO6A  x1
PK6A  x1
SCID  x1
P37A  x1
P07A  x1
PH7A  x1
PJ7A  x1
PB8A  x1
PG8A  x1
PH8A  x1
PI8A  x1
JSFQ  x1
XWFJ  x1
TUUU  x1
UUUU  x1
UUUE  x1
HIGH  x1
ANSI  x1
LEFT  x1
HAND  x1
LN10  x1
ANON  x1
AUTH  x1
IPAD  x1
TCIP  x1
AQUA  x1
PURH  x1
YAML  x1
M8MF  x1
NONE  x1
MAYA  x1
MESH  x1
PLUM  x1
BLUE  x1
NAVY  x1
TEAL  x1
CYAN  x1
LIME  x1
GOLD  x1
SNOW  x1
PERU  x1
PINK  x1
GRAY  x1
GREY  x1
QUAD  x1
LIST  x1
MOPP  x1
USER  x1
DONE  x1
PNLA  x1
XMPP  x1
EALS  x1
CHAT  x1
BUSY  x1
IDLE  x1
DOWN  x1
EAID  x1
MISC  x1
MAIL  x1
USED  x1
SKUD  x1
MALE  x1
WEAK  x1
HTML  x1
INFO  x1
COPY  x1
BOTH  x1
HTTP  x1
DIME  x1
CLNT  x1
SRVR  x1
FORM  x1
AIFF  x1
COMM  x1
INST  x1
SSND  x1
HRTF  x1
HDMI  x1
FFIA  x1
E254  x1
RSDS  x1
M59P  x1
Z92P  x1
O011  x1
YK22  x1
FIBH  x1
UZG9  x1
N0VP  x1
U7KE  x1
QO85  x1
ZCYC  x1
LH0W  x1
MONI  x1
WW6T  x1
FGDP  x1
D4O6  x1
Z2YD  x1
PXOC  x1
ECZC  x1
L27Q  x1
T3BH  x1
G9O2  x1
CHNB  x1
V0PO  x1
YIJG  x1
W98Q  x1
JXL0  x1
V3V0  x1
BGG1  x1
KPA2  x1
PNX9  x1
Y2L1  x1
TA5G  x1
KP6J  x1
ZYSW  x1
TUD4  x1
YCMI  x1
OVEN  x1
Z7DO  x1
RNHZ  x1
BQPC  x1
U3WK  x1
HBEC  x1
C3GH  x1
ZU98  x1
PXO6  x1
PUMC  x1
CVI8  x1
UEK4  x1
EXQJ  x1
OOMG  x1
DHT7  x1
J2K0  x1
K5NY  x1
LSYR  x1
E7CC  x1
OC09  x1
GSHG  x1
XDMV  x1
POKZ  x1
XEYR  x1
OQKB  x1
EINE  x1
WHBW  x1
GMGC  x1
RXU8  x1
U0TY  x1
QNK7  x1
KO91  x1
QRU3  x1
ZGFU  x1
PX4T  x1
DR1G  x1
EY49  x1
J6BG  x1
SES4  x1
Y02A  x1
TS6P  x1
NKZF  x1
UVS2  x1
KNHE  x1
GY1I  x1
SQ83  x1
SAV7  x1
TRYK  x1
KTG7  x1
PI6H  x1
KQR6  x1
MEXI  x1
HTYL  x1
CBYJ  x1
XJFZ  x1
N7U2  x1
G18U  x1
MZTN  x1
BV5Z  x1
QDI8  x1
D13D  x1
ORKN  x1
EL76  x1
LTDS  x1
FAXX  x1
LJWM  x1
VU3F  x1
IMOH  x1
M4NC  x1
RI68  x1
FVOO  x1
X5UY  x1
WE2E  x1
SX5E  x1
C27Q  x1
UWY4  x1
HA8H  x1
LUJY  x1
VHI2  x1
LLT1  x1
MPJS  x1
O9MV  x1
GQWQ  x1
SBQJ  x1
H2NF  x1
LGLH  x1
IMD4  x1
GGKD  x1
G7ZK  x1
HC5Q  x1
DX2B  x1
KC1I  x1
UGDN  x1
THX2  x1
TM4L  x1
PL2F  x1
H62X  x1
MZ5Z  x1
O2DU  x1
BTYR  x1
Y3MB  x1
RVG1  x1
HNSO  x1
FUMR  x1
Q1NI  x1
T4QL  x1
TUBL  x1
MFSZ  x1
VKG0  x1
B0HH  x1
MJAR  x1
CLPI  x1
S5P3  x1
LQ5U  x1
L9CX  x1
RVQ3  x1
GE10  x1
VT5A  x1
RMA7  x1
K36W  x1
FQ1V  x1
LTX9  x1
DYM8  x1
VB85  x1
M8WQ  x1
BS8Q  x1
EJY0  x1
P11R  x1
S2OP  x1
D0Z4  x1
T2KM  x1
L6G9  x1
FYT7  x1
K2GK  x1
GTWT  x1
QVV0  x1
ZPAX  x1
I0QA  x1
ZS9I  x1
TZOL  x1
LB57  x1
H77H  x1
UBLT  x1
MNC7  x1
J7JD  x1
YY68  x1
HBVM  x1
MOG3  x1
GAK1  x1
J0B9  x1
CPN5  x1
PA0J  x1
NFAA  x1
ALEY  x1
BX0D  x1
UEJF  x1
JKGE  x1
Q0QZ  x1
ZIFI  x1
HWB9  x1
T7GE  x1
G9WG  x1
LV92  x1
KAO3  x1
XY2P  x1
MEGX  x1
DTOG  x1
TXG7  x1
BO5S  x1
J5MB  x1
NFHX  x1
LM9Z  x1
GVXT  x1
QRPW  x1
JQWL  x1
W24G  x1
OSXC  x1
ZQ45  x1
MZ26  x1
D022  x1
NA06  x1
XE34  x1
```
