# TDF classes and their fields (reconstructed from NFS14.exe)

> Older heuristic (table boundaries from `lea` instructions): it glues neighbouring classes together. The exact boundaries come from `tools/tdf_classes.py` (a record with `meta[1] == 0` ends its class) - see docs/protocol.md, section 3.

- Field records: **2,864**
- Detected tables (boundaries from `lea` instructions in the code): **352**
- Named classes: **5**

Field order is the order from the table, i.e. the TDF encoding order. `meta` is the record's 4 bytes of metadata (candidates: type code, field offset in the structure, size).

## (unnamed table @ 0x0001416ac880)

`0x0001416ac880` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `EAMC` | mEaMayContact | `15 18 10 00` |
| `PMC ` | mPartnersMayContact | `15 00 14 00` |
| `PID ` | mPersonaId | `16 00 10 00` |

## (unnamed table @ 0x0001416ac928)

`0x0001416ac928` - 13 fields

| tag | field | meta |
| --- | --- | --- |
| `MAIL` | mEmail | `05 20 10 00` |
| `PLST` | mPersonaDetailsList | `02 00 20 00` |
| `ACNT` | mAchievements | `15 18 10 00` |
| `EPTS` | mExperience | `16 18 20 00` |
| `RPTS` | mRewardPoints | `16 00 18 00` |
| `DESC` | mDesc | `05 20 48 00` |
| `HOWT` | mHowto | `05 20 58 00` |
| `IMG ` | mImg | `05 20 28 00` |
| `META` | mMeta | `05 20 68 00` |
| `NAME` | mName | `05 20 38 00` |
| `RPTS` | mRp | `16 18 18 00` |
| `XPTS` | mXp | `16 00 20 00` |
| `LSDT` | mListsInfo | `02 00 10 00` |

## (unnamed table @ 0x0001416acc70)

`0x0001416acc70` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `CREQ` | mCreateAccountParameters | `0a 18 10 00` |
| `MAC ` | mMacAddress | `05 20 c8 01` |
| `PERS` | mExtName | `05 20 b8 01` |
| `PLOC` | mPlatformLocale | `13 18 98 01` |
| `TICK` | mTicketBlob | `08 10 a0 01` |
| `XREF` | mExtId | `17 00 90 01` |

## (unnamed table @ 0x0001416acd10)

`0x0001416acd10` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `INFO` | mInfo | `0a 18 10 00` |
| `MEML` | mListMemberInfoVector | `02 18 88 00` |
| `OFRC` | mOffset | `15 18 e4 00` |
| `TOCT` | mTotalCount | `15 00 e0 00` |
| `CUR ` | mCurrent | `16 18 18 00` |
| `PTS ` | mPoints | `16 00 10 00` |

## (unnamed table @ 0x0001416acda0)

`0x0001416acda0` - 12 fields

| tag | field | meta |
| --- | --- | --- |
| `LMID` | mListMemberId | `0a 18 18 00` |
| `TIME` | mTimeAdded | `16 00 10 00` |
| `UIOP` | mBlazeUserIdOrPersonaName | `09 00 10 00` |
| `DTOK` | mXBLToken | `05 20 10 00` |
| `PROF` | mProofKey | `05 00 20 00` |
| `ACHS` | mHistory | `02 00 10 00` |
| `BIDS` | mBlazeIds | `02 00 10 00` |
| `BUID` | mUserId | `18 18 10 00` |
| `ETAG` | mEntitlementTag | `05 20 48 00` |
| `GNAM` | mGroupName | `05 20 38 00` |
| `PJID` | mProjectId | `05 20 28 00` |
| `PRID` | mProductId | `05 00 18 00` |

## (unnamed table @ 0x0001416acfc8)

`0x0001416acfc8` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `LNM ` | mListName | `05 20 18 00` |
| `TYPE` | mListType | `13 00 10 00` |

## (unnamed table @ 0x0001416ad240)

`0x0001416ad240` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `BUID` | mBlazeUserId | `18 18 20 00` |
| `FRST` | mIsFirstLogin | `0f 18 40 00` |
| `KEY ` | mSessionKey | `05 20 10 00` |
| `LLOG` | mLastLoginDateTime | `16 18 48 00` |
| `MAIL` | mEmail | `05 20 30 00` |
| `PDTL` | mPersonaDetails | `0a 18 50 00` |
| `UID ` | mUserId | `16 00 28 00` |

## (unnamed table @ 0x0001416ad300)

`0x0001416ad300` - 15 fields

| tag | field | meta |
| --- | --- | --- |
| `LDVC` | mLegalDocVersion | `05 20 28 00` |
| `TCOL` | mLegalDocContentLength | `15 18 10 00` |
| `TCOT` | mLegalDocContent | `05 00 18 00` |
| `UCNT` | mUseCount | `15 00 10 00` |
| `AHID` | mAchieveId | `05 20 40 00` |
| `AUXA` | mAuxAuth | `0a 18 88 00` |
| `LANG` | mLanguage | `05 20 50 00` |
| `META` | mIncludeMetadata | `0e 18 60 00` |
| `PROD` | mProductId | `05 20 30 00` |
| `PROG` | mProgress | `0a 18 68 00` |
| `USER` | mUser | `0a 00 10 00` |
| `MAIL` | mEmail | `05 20 10 00` |
| `OPT1` | mGlobalOptin | `10 18 30 00` |
| `OPT3` | mThirdPartyOptin | `10 18 31 00` |
| `PASS` | mPassword | `05 00 20 00` |

## (unnamed table @ 0x0001416ad4f0)

`0x0001416ad4f0` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `BID ` | mBlazeId | `18 18 10 00` |
| `BIDL` | mListMemberIdVector | `02 18 40 00` |
| `HASH` | mMemberHash | `15 18 98 00` |
| `LID ` | mListIdentification | `0a 18 18 00` |
| `VALD` | mValidateDelete | `0e 00 9c 00` |

## (unnamed table @ 0x0001416ad588)

`0x0001416ad588` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `LIST` | mList | `02 00 10 00` |
| `BID ` | mMemberBlazeId | `18 18 60 00` |
| `LBID` | mOwnersBlazeIds | `0a 18 10 00` |
| `LID ` | mListIdentification | `0a 00 68 00` |

## (unnamed table @ 0x0001416ad6c0)

`0x0001416ad6c0` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `ALST` | mListInfoVector | `02 18 10 00` |
| `MXRC` | mMaxResultCount | `15 18 68 00` |
| `OFRC` | mOffset | `15 00 6c 00` |

## (unnamed table @ 0x0001416ad710)

`0x0001416ad710` - 17 fields

| tag | field | meta |
| --- | --- | --- |
| `PRMF` | mFloatParamList | `02 18 98 00` |
| `PRMI` | mInt32ParamList | `02 18 18 00` |
| `PRMS` | mStringParamList | `02 18 d8 00` |
| `PRMU` | mUint64ParamList | `02 18 58 00` |
| `TYPE` | mMessageType | `14 00 10 00` |
| `SUGG` | mSuggestions | `02 00 10 00` |
| `BDAY` | mBirthDay | `14 18 3c 00` |
| `BMON` | mBirthMonth | `14 18 38 00` |
| `BYR ` | mBirthYear | `14 18 40 00` |
| `MORP` | mEmailOrOriginPersona | `05 20 10 00` |
| `PASS` | mPassword | `05 20 20 00` |
| `PERS` | mExtName | `05 20 60 00` |
| `TICK` | mTicketBlob | `08 10 48 00` |
| `XREF` | mExtId | `17 00 30 00` |
| `ATTS` | mAdditionalAttributesList | `02 18 20 00` |
| `BASE` | mBaseName | `05 20 10 00` |
| `NSUG` | mNumberSuggestions | `15 00 60 00` |

## (unnamed table @ 0x0001416ad8c0)

`0x0001416ad8c0` - 12 fields

| tag | field | meta |
| --- | --- | --- |
| `BID ` | mOwnerId | `18 18 10 00` |
| `LMID` | mListMemberInfoVector | `02 18 20 00` |
| `REM ` | mRemovedListMemberIdVector | `02 18 78 00` |
| `TYPE` | mListType | `13 00 18 00` |
| `UCTC` | mUseCountConsumed | `15 18 14 00` |
| `UCTR` | mUseCountRemain | `15 00 10 00` |
| `AUXA` | mAuxAuth | `0a 18 b0 00` |
| `CPAY` | mCustomPayload | `05 20 a0 00` |
| `PROD` | mProductId | `05 20 30 00` |
| `TYPE` | mStringType | `05 20 40 00` |
| `USER` | mUser | `0a 18 10 00` |
| `WINC` | mWincodes | `01 00 50 00` |

## (unnamed table @ 0x0001416ad9f8)

`0x0001416ad9f8` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `AUTH` | mAuthToken | `05 00 10 00` |
| `BID ` | mOwnerBlazeId | `18 18 60 00` |
| `LBID` | mMembersBlazeIds | `0a 18 10 00` |
| `LID ` | mListIdentification | `0a 00 68 00` |
| `GTAG` | mGamerTag | `05 20 18 00` |
| `XUID` | mXuid | `17 00 10 00` |

## (unnamed table @ 0x0001416adaa0)

`0x0001416adaa0` - 14 fields

| tag | field | meta |
| --- | --- | --- |
| `BDAY` | mBirthDay | `14 18 34 00` |
| `BMON` | mBirthMonth | `14 18 30 00` |
| `BYR ` | mBirthYear | `14 18 38 00` |
| `CTRY` | mIsoCountryCode | `05 20 40 00` |
| `LANG` | mIsoLanguageCode | `05 20 50 00` |
| `MAIL` | mEmail | `05 20 10 00` |
| `OPT1` | mEaEmailAllowed | `11 18 80 00` |
| `OPT3` | mThirdPartyEmailAllowed | `11 18 81 00` |
| `PASS` | mPassword | `05 20 20 00` |
| `PNAM` | mPersonaName | `05 20 70 01` |
| `PRIV` | mPrivacyPolicyUri | `05 20 70 00` |
| `PRNT` | mParentalEmail | `05 20 88 00` |
| `PROF` | mUserProfileInfo | `0a 18 98 00` |
| `TSUI` | mTermsOfServiceUri | `05 00 60 00` |

## (unnamed table @ 0x0001416adc30)

`0x0001416adc30` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `AUTH` | mAuthCode | `05 20 10 00` |
| `EXTB` | mExternalBlob | `08 10 28 00` |
| `EXTI` | mExternalId | `17 00 20 00` |

## (unnamed table @ 0x0001416adc80)

`0x0001416adc80` - 9 fields

| tag | field | meta |
| --- | --- | --- |
| `CPWD` | mCurrentPassword | `05 20 78 00` |
| `CTRY` | mCountry | `05 20 40 00` |
| `DOB ` | mDOB | `05 20 30 00` |
| `LANG` | mLanguage | `05 20 50 00` |
| `MAIL` | mEmail | `05 20 10 00` |
| `OPT1` | mGlobalOptin | `10 18 70 00` |
| `OPT3` | mThirdPartyOptin | `10 18 71 00` |
| `PASS` | mPassword | `05 20 20 00` |
| `PRNT` | mParentalEmail | `05 00 60 00` |

## (unnamed table @ 0x0001416add90)

`0x0001416add90` - 16 fields

| tag | field | meta |
| --- | --- | --- |
| `BOID` | mBlazeObjId | `0c 10 68 00` |
| `FLGS` | mStatusFlags | `07 10 40 00` |
| `LID ` | mId | `0a 18 10 00` |
| `LMS ` | mMaxSize | `15 18 38 00` |
| `PNAM` | mPairName | `05 20 58 00` |
| `PRID` | mPairId | `13 00 50 00` |
| `PNAM` | mPersonaName | `05 20 18 00` |
| `UID ` | mUserId | `16 00 10 00` |
| `ID  ` | mId | `13 18 20 00` |
| `MUTA` | mMutualAction | `0e 18 2a 00` |
| `NAME` | mName | `05 20 10 00` |
| `OFFL` | mLoadOfflineUED | `0e 18 2e 00` |
| `PRID` | mPairId | `13 18 2c 00` |
| `ROLL` | mRollover | `0e 18 28 00` |
| `SCRI` | mSubscribe | `0e 18 29 00` |
| `SIZE` | mMaxSize | `15 00 24 00` |

## (unnamed table @ 0x0001416adf18)

`0x0001416adf18` - 8 fields

| tag | field | meta |
| --- | --- | --- |
| `INFO` | mAccountInfo | `0a 18 20 00` |
| `PCTK` | mPCLoginToken | `05 00 10 00` |
| `BDAY` | mBirthDay | `14 18 24 00` |
| `BMON` | mBirthMonth | `14 18 20 00` |
| `BYR ` | mBirthYear | `14 18 28 00` |
| `CTRY` | mIsoCountryCode | `05 00 10 00` |
| `BID ` | mBlazeId | `18 18 10 00` |
| `LID ` | mListIdentification | `0a 00 18 00` |

## (unnamed table @ 0x0001416adfe8)

`0x0001416adfe8` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `NLST` | mEntitlements | `02 00 10 00` |

## (unnamed table @ 0x0001416ae000)

`0x0001416ae000` - 28 fields

| tag | field | meta |
| --- | --- | --- |
| `MAIL` | mEmail | `05 20 10 00` |
| `PASS` | mPassword | `05 20 20 00` |
| `PNAM` | mPersonaName | `05 00 30 00` |
| `DEUC` | mDecrementCount | `15 18 50 00` |
| `ETAG` | mEntitlementTag | `05 20 40 00` |
| `GNAM` | mGroupName | `05 20 30 00` |
| `PJID` | mProjectId | `05 20 20 00` |
| `PRID` | mProductId | `05 00 10 00` |
| `AUXA` | mAuxAuth | `0a 18 58 00` |
| `LANG` | mLanguage | `05 20 30 00` |
| `LIMT` | mLimit | `15 18 50 00` |
| `PROD` | mProductIds | `05 20 40 00` |
| `STRT` | mStart | `15 18 54 00` |
| `USER` | mUser | `0a 00 10 00` |
| `BID ` | mBlazeId | `18 18 10 00` |
| `HASH` | mMemberHash | `15 18 1c 00` |
| `TYPE` | mListType | `13 00 18 00` |
| `SPAM` | mIsOfLegalContactAge | `11 18 10 00` |
| `UAGE` | mIsUnderage | `0f 18 11 00` |
| `UNDR` | mIsUnderageSupported | `0f 00 12 00` |
| `VALU` | mOptInValue | `0f 00 10 00` |
| `MAIL` | mEmail | `05 20 10 00` |
| `NUID` | mNucleusId | `17 18 30 00` |
| `PNAM` | mPersonaName | `05 00 20 00` |
| `GTAG` | mGamerTag | `05 20 18 00` |
| `MAC ` | mMacAddress | `05 20 38 00` |
| `PASS` | mPassword | `05 20 28 00` |
| `XUID` | mXuid | `17 00 10 00` |

## (unnamed table @ 0x0001416ae368)

`0x0001416ae368` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `BID ` | mBlazeId | `18 18 10 00` |
| `LIDS` | mListIdentificationVector | `02 00 18 00` |

## (unnamed table @ 0x0001416ae3a0)

`0x0001416ae3a0` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `BUID` | mBlazeUserId | `18 18 20 00` |
| `FRST` | mIsFirstLogin | `0f 18 40 00` |
| `KEY ` | mSessionKey | `05 20 10 00` |
| `LLOG` | mLastLoginDateTime | `16 18 48 00` |
| `MAIL` | mEmail | `05 20 30 00` |
| `PDTL` | mPersonaDetails | `0a 18 50 00` |
| `UID ` | mUserId | `16 00 28 00` |

## (unnamed table @ 0x0001416ae460)

`0x0001416ae460` - 11 fields

| tag | field | meta |
| --- | --- | --- |
| `MAXS` | mMaxLength | `13 18 12 00` |
| `MIND` | mMinDigits | `13 18 18 00` |
| `MINL` | mMinLowerCharacters | `13 18 14 00` |
| `MINS` | mMinLength | `13 18 10 00` |
| `MINU` | mMinUpperCharacters | `13 18 16 00` |
| `VDCH` | mValidCharacters | `05 00 20 00` |
| `MAIL` | mEmail | `05 00 10 00` |
| `BID ` | mBlazeId | `18 18 10 00` |
| `LID ` | mListIdentification | `0a 18 18 00` |
| `MXRC` | mMaxResultCount | `15 18 40 00` |
| `OFRC` | mOffset | `15 00 44 00` |

## (unnamed table @ 0x0001416ae580)

`0x0001416ae580` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `CDKY` | mIsCdKey | `0f 18 41 00` |
| `GNAM` | mGroupName | `05 20 30 00` |
| `KEY ` | mCode | `05 20 10 00` |
| `PID ` | mProductId | `05 20 20 00` |
| `PNID` | mIsBindPersona | `0f 00 40 00` |
| `TCKT` | mPS3Ticket | `08 00 10 00` |

## (unnamed table @ 0x0001416ae620)

`0x0001416ae620` - 13 fields

| tag | field | meta |
| --- | --- | --- |
| `AGUP` | mCanAgeUp | `0f 18 b0 00` |
| `ANON` | mIsAnonymous | `0f 18 b2 00` |
| `NTOS` | mNeedsLegalDoc | `0f 18 b4 00` |
| `PCTK` | mPCLoginToken | `05 20 10 00` |
| `SESS` | mSessionInfo | `0a 18 20 00` |
| `SPAM` | mIsOfLegalContactAge | `0f 18 b3 00` |
| `UNDR` | mIsUnderage | `0f 00 b1 00` |
| `BUID` | mUserId | `18 18 10 00` |
| `EPSN` | mPageNo | `13 18 6a 00` |
| `EPSZ` | mPageSize | `13 18 68 00` |
| `FLAG` | mEntitlementSearchFlag | `07 10 58 00` |
| `GNLS` | mGroupNameList | `02 00 18 00` |
| `NAME` | mOptInName | `05 00 10 00` |

## (unnamed table @ 0x0001416ae790)

`0x0001416ae790` - 15 fields

| tag | field | meta |
| --- | --- | --- |
| `ANON` | mIsAnonymous | `0f 18 12 00` |
| `NTOS` | mNeedsLegalDoc | `0f 18 13 00` |
| `SESS` | mSessionInfo | `0a 18 18 00` |
| `SPAM` | mIsOfLegalContactAge | `0f 18 10 00` |
| `UNDR` | mIsUnderage | `0f 00 11 00` |
| `MAC ` | mMacAddress | `05 20 38 00` |
| `PASS` | mPassword | `05 20 28 00` |
| `TCKT` | mPS3Ticket | `08 00 10 00` |
| `AGUP` | mCanAgeUp | `0f 18 a0 00` |
| `ANON` | mIsAnonymous | `0f 18 a2 00` |
| `NTOS` | mNeedsLegalDoc | `0f 18 a4 00` |
| `SESS` | mSessionInfo | `0a 18 10 00` |
| `SPAM` | mIsOfLegalContactAge | `0f 18 a3 00` |
| `UNDR` | mIsUnderage | `0f 00 a1 00` |
| `SKEY` | mSessionKey | `05 00 10 00` |

## (unnamed table @ 0x0001416aea20)

`0x0001416aea20` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `ENTI` | mEntitlementInfo | `0a 18 10 00` |
| `ISGR` | mIsGranted | `0f 00 c0 00` |
| `PINF` | mPersonaInfo | `0a 18 18 00` |
| `UID ` | mUserId | `16 00 10 00` |

## (unnamed table @ 0x0001416aeb50)

`0x0001416aeb50` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `LMAP` | mListMembersVector | `02 00 10 00` |

## (unnamed table @ 0x0001416aeb70)

`0x0001416aeb70` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `PRIV` | mPrivacyPolicyUri | `05 20 20 00` |
| `TSUI` | mTermsOfServiceUri | `05 00 10 00` |
| `TURI` | mLegalDocUri | `05 00 10 00` |
| `CLID` | mClubId | `17 18 10 00` |
| `RCID` | mRecordIdList | `02 00 18 00` |

## (unnamed table @ 0x0001416b4da8)

`0x0001416b4da8` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `BLID` | mBlazeId | `18 00 10 00` |
| `CUNT` | mCount | `15 00 10 00` |
| `CLID` | mClubId | `17 18 10 00` |
| `PSWD` | mPassword | `05 00 18 00` |

## (unnamed table @ 0x0001416b4ef0)

`0x0001416b4ef0` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `BLIS` | mBlazeId | `18 00 10 00` |

## (unnamed table @ 0x0001416b4f08)

`0x0001416b4f08` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `SUCC` | mMbSuccess | `0e 00 10 00` |
| `ISSP` | mIsItemSpecial | `0e 18 1c 00` |
| `SCID` | mItemScopeValue | `15 18 14 00` |
| `SPID` | mSpecialEventId | `15 18 20 00` |
| `TIMA` | mTimeItemAdded | `15 18 18 00` |
| `TYPE` | mItemType | `11 00 10 00` |
| `CLID` | mClubId | `17 00 10 00` |

## (unnamed table @ 0x0001416b4fb0)

`0x0001416b4fb0` - 9 fields

| tag | field | meta |
| --- | --- | --- |
| `FDCD` | mFeedbackCode | `14 18 1c 00` |
| `INTL` | mIntList | `02 18 20 00` |
| `WPID` | mWeaponId | `17 18 10 00` |
| `WPTY` | mWeaponType | `15 00 18 00` |
| `CLID` | mClubId | `17 00 10 00` |
| `CLID` | mClubId | `17 18 10 00` |
| `CLST` | mClubSettings | `0a 18 18 00` |
| `CLTG` | mTagList | `02 00 20 01` |
| `PERM` | mPermissionsByAdminTypeMap | `01 00 10 00` |

## (unnamed table @ 0x0001416b50c0)

`0x0001416b50c0` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `DATA` | mBlob | `08 10 20 00` |
| `MIME` | mContentType | `05 00 10 00` |
| `ROWS` | mSpeedwalls | `02 00 10 00` |

## (unnamed table @ 0x0001416b5138)

`0x0001416b5138` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `SUCC` | mMbSuccess | `0e 00 10 00` |
| `MESS` | mResponseMessage | `05 20 18 00` |
| `SUCC` | mMbSuccess | `0e 00 10 00` |
| `CLID` | mClubId | `17 00 10 00` |
| `IDLT` | mBlazeIdList | `02 00 10 00` |
| `SUCC` | mPlayerOnlineList | `02 00 10 00` |

## (unnamed table @ 0x0001416b5278)

`0x0001416b5278` - 21 fields

| tag | field | meta |
| --- | --- | --- |
| `SUCC` | mMbSuccess | `0e 00 10 00` |
| `CMLS` | mClubMemberList | `02 18 10 00` |
| `TCON` | mTotalCount | `15 00 68 00` |
| `SUCC` | mMbSuccess | `0e 00 10 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `VAL ` | mValue | `15 00 18 00` |
| `MSG ` | mMessage | `05 00 10 00` |
| `CLID` | mClubId | `17 18 10 00` |
| `PIJF` | mPetitionIfJoinFails | `0f 18 28 00` |
| `PSWD` | mPassword | `05 00 18 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `EVBY` | mBounty | `14 18 5c 00` |
| `EVNT` | mEvent | `15 18 50 00` |
| `EVTM` | mTimeMs | `14 18 58 00` |
| `GEN ` | mGenerator | `05 20 30 00` |
| `PARM` | mStoryParamsMap | `01 18 60 00` |
| `POST` | mPosterId | `18 18 18 00` |
| `PRIO` | mPriority | `15 18 54 00` |
| `SUBJ` | mSubject | `05 20 40 00` |
| `TIME` | mTimestamp | `05 00 20 00` |
| `BLID` | mBlazeId | `18 00 10 00` |

## (unnamed table @ 0x0001416b54a0)

`0x0001416b54a0` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `BLID` | mBlazeId | `18 00 10 00` |

## (unnamed table @ 0x0001416b54b8)

`0x0001416b54b8` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `RESP` | mSuccess | `0e 00 10 00` |

## (unnamed table @ 0x0001416b54d0)

`0x0001416b54d0` - 12 fields

| tag | field | meta |
| --- | --- | --- |
| `BLUS` | mBlazeUser | `0a 18 d8 00` |
| `EXBL` | mExternalBlob | `08 10 c0 00` |
| `MUBF` | mMutualFriends | `02 18 60 00` |
| `PLID` | mPlatformUserID | `17 18 b8 00` |
| `STAF` | mStatsFlt | `01 00 10 00` |
| `CLID` | mClubId | `17 00 10 00` |
| `ADMN` | mAdminEmail | `05 20 10 00` |
| `AUTH` | mAuthCredentials | `0a 00 20 00` |
| `TDFL` | mCensusDataList | `02 00 10 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `PLST` | mPlaylist | `15 18 28 00` |
| `TYPE` | mType | `05 00 18 00` |

## (unnamed table @ 0x0001416b5630)

`0x0001416b5630` - 13 fields

| tag | field | meta |
| --- | --- | --- |
| `BLID` | mBlazeId | `18 18 10 00` |
| `LANG` | mLanguageCode | `15 00 18 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `REQS` | mScoreRequests | `02 00 18 00` |
| `BIDS` | mBlazeIds | `02 00 10 00` |
| `ACID` | mAccountID | `16 00 10 00` |
| `WPID` | mWeaponId | `17 00 10 00` |
| `CONT` | mCount | `15 18 14 00` |
| `SQID` | mSequenceID | `15 18 10 00` |
| `TCON` | mTotalCount | `15 00 18 00` |
| `LPMP` | mClubPetitionListMap | `01 00 10 00` |
| `NWLI` | mLocalizedNewsList | `02 18 10 00` |
| `TLPG` | mTotalPages | `13 00 68 00` |

## (unnamed table @ 0x0001416b5778)

`0x0001416b5778` - 9 fields

| tag | field | meta |
| --- | --- | --- |
| `ADMN` | mAdminEmail | `05 20 10 00` |
| `MAP ` | mAdminTypeListByContextMap | `01 00 20 00` |
| `AUTH` | mAuthCredentials | `0a 18 98 00` |
| `CAT ` | mCategoryName | `05 20 20 00` |
| `CTXT` | mContext | `05 20 10 00` |
| `NAME` | mRecord | `05 20 30 00` |
| `OWNR` | mOwners | `02 00 40 00` |
| `MAP ` | mAdminTypeListByContextMap | `01 18 10 00` |
| `PERM` | mPermissionsByAdminTypeMap | `01 00 78 00` |

## (unnamed table @ 0x0001416b5870)

`0x0001416b5870` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `SPWA` | mSpeedwalls | `02 00 10 00` |
| `GENS` | mBillboardLeaderResponseList | `02 00 10 00` |
| `AWCS` | mAwardChecksum | `15 18 38 00` |
| `AWID` | mAwardId | `15 18 10 00` |
| `AWNA` | mAwardName | `05 20 18 00` |
| `AWUR` | mAwardURL | `05 00 28 00` |

## (unnamed table @ 0x0001416b5910)

`0x0001416b5910` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `RESP` | mInGameRealtimePresenceResponseList | `02 00 10 00` |
| `EVNT` | mEvent | `15 18 10 00` |
| `TIME` | mTimeMs | `14 18 14 00` |
| `UINF` | mUserInfo | `15 00 18 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `NUM ` | mNumNotifications | `11 00 18 00` |
| `CLID` | mClubId | `17 00 10 00` |

## (unnamed table @ 0x0001416b59c0)

`0x0001416b59c0` - 30 fields

| tag | field | meta |
| --- | --- | --- |
| `CIHA` | mCityHash | `17 18 30 00` |
| `GECI` | mGeoCity | `05 20 10 00` |
| `GECO` | mGeoCountry | `05 00 20 00` |
| `CLID` | mClubId | `17 00 10 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `NUM ` | mCompletedEventCount | `11 18 20 00` |
| `TOTB` | mTotalBounty | `14 18 1c 00` |
| `TOTL` | mTotalTimeMs | `14 00 18 00` |
| `ASC ` | mSmallerIsBetter | `0e 18 b8 00` |
| `CATE` | mCategory | `05 20 10 00` |
| `KEYS` | mColumns | `01 18 50 00` |
| `LBRD` | mLeaderboard | `05 20 20 00` |
| `OCAT` | mOnlineCategory | `05 20 30 00` |
| `OLBD` | mOnlineLeaderboard | `05 00 40 00` |
| `BNTY` | mBestBounty | `14 18 38 00` |
| `EVNT` | mEvent | `15 18 20 00` |
| `FRDS` | mNumFriends | `11 18 3c 00` |
| `GEN ` | mGenerator | `05 20 10 00` |
| `TIME` | mBestTimeMs | `14 18 24 00` |
| `TIST` | mTimeStampMs | `05 00 28 00` |
| `MMBR` | mClubMember | `0a 18 18 00` |
| `SQID` | mSequenceID | `15 00 10 00` |
| `LIST` | mContexts | `02 00 10 00` |
| `CIDL` | mClubIdList | `02 18 10 00` |
| `TSTM` | mOldestTimestamp | `15 00 50 00` |
| `FDCD` | mFeedbackCode | `14 18 24 00` |
| `INTL` | mIntList | `02 18 28 00` |
| `RESP` | mSuccess | `0e 18 10 00` |
| `WPID` | mWeaponId | `17 18 18 00` |
| `WPTY` | mWeaponType | `15 00 20 00` |

## (unnamed table @ 0x0001416b5d08)

`0x0001416b5d08` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `BLID` | mBlazeId | `18 00 10 00` |

## (unnamed table @ 0x0001416b5d20)

`0x0001416b5d20` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `BLUS` | mRivalBlazeUser | `0a 18 88 00` |
| `PENA` | mRivalName | `05 20 78 00` |
| `PLSC` | mPlayerScore | `15 18 68 00` |
| `RECM` | mRecommendationsList | `02 18 10 00` |
| `RIBL` | mRivalBlazeId | `18 18 70 00` |
| `RISC` | mRivalScore | `15 00 6c 00` |
| `CMSL` | mClubMembershipList | `02 00 10 00` |

## (unnamed table @ 0x0001416b5dd0)

`0x0001416b5dd0` - 15 fields

| tag | field | meta |
| --- | --- | --- |
| `AMOA` | mWeaponAAmmo | `10 18 20 01` |
| `AMOB` | mWeaponBAmmo | `10 18 21 01` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `DBG ` | mShowDebug | `0e 18 68 01` |
| `GETP` | mFriendBlazeIdList | `02 18 28 01` |
| `HEAL` | mHealthLevel | `10 18 1d 01` |
| `NITR` | mNitrousLevel | `10 18 1c 01` |
| `POSR` | mPosRList | `02 18 98 00` |
| `POSX` | mPosXList | `02 18 18 00` |
| `POSZ` | mPosZList | `02 18 58 00` |
| `STTE` | mGameStateField | `11 18 22 01` |
| `TIMA` | mTimeAnimate | `14 18 18 01` |
| `TIML` | mTimestampList | `02 18 d8 00` |
| `WEPA` | mWeaponAId | `10 18 1e 01` |
| `WEPB` | mWeaponBId | `10 00 1f 01` |

## (unnamed table @ 0x0001416b5f38)

`0x0001416b5f38` - 44 fields

| tag | field | meta |
| --- | --- | --- |
| `BLID` | mBlazeId | `18 18 10 00` |
| `STTS` | mOverwatchStats | `01 00 18 00` |
| `RCRE` | mResourceCreated | `0e 18 10 00` |
| `TYPE` | mAdmin | `0a 00 18 00` |
| `STOR` | mStories | `02 00 10 00` |
| `BLID` | mBlazeId | `18 00 10 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `DBG ` | mShowDebug | `0e 18 58 00` |
| `PLID` | mPlayerBlazeIdList | `02 00 18 00` |
| `LIST` | mCategories | `02 00 10 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `EVNT` | mEvent | `15 18 24 00` |
| `FRND` | mGetFriendStory | `0e 18 20 00` |
| `GEN ` | mGenerator | `05 20 28 00` |
| `POST` | mPosterId | `18 00 18 00` |
| `DIVN` | mDivision | `15 18 10 00` |
| `SRNK` | mStartingRank | `15 00 14 00` |
| `AUTH` | mAuthCredentials | `0a 18 20 00` |
| `CTXT` | mContext | `05 00 10 00` |
| `LIST` | mAdminChangeEventList | `02 00 10 00` |
| `ROWS` | mSpeedwalls | `02 00 10 00` |
| `NMAP` | mNestedMap | `01 18 78 00` |
| `NUM ` | mNum | `14 18 10 00` |
| `SMAP` | mStringMap | `01 18 28 00` |
| `TEXT` | mText | `05 00 18 00` |
| `BLID` | mBlazeId | `18 00 10 00` |
| `BLID` | mBlazeId | `18 00 10 00` |
| `ATTS` | mNumAttempts | `11 18 20 00` |
| `EVNT` | mEvent | `15 18 18 00` |
| `FRND` | mBlazeId | `18 18 10 00` |
| `TIME` | mTimestamp | `15 18 1c 00` |
| `TIST` | mTimeStampMs | `05 00 28 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `REQ ` | mSpeedwalls | `02 00 18 00` |
| `AUTH` | mAuthCredentials | `0a 18 40 00` |
| `CTXT` | mContext | `05 20 10 00` |
| `DESC` | mDescription | `05 20 30 00` |
| `LABL` | mLabel | `05 20 20 00` |
| `VERS` | mVersion | `15 00 88 00` |
| `BANS` | mClubIdToBanStatusMap | `01 00 10 00` |
| `CLID` | mClubId | `17 18 10 00` |
| `DMID` | mClubDomainId | `15 18 18 00` |
| `MBER` | mClubMember | `0a 18 30 00` |
| `NAME` | mClubName | `05 00 20 00` |

## (unnamed table @ 0x0001416b64c8)

`0x0001416b64c8` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `BLID` | mBlazeId | `18 00 10 00` |

## (unnamed table @ 0x0001416b6550)

`0x0001416b6550` - 45 fields

| tag | field | meta |
| --- | --- | --- |
| `STTS` | mOverwatchStats | `01 18 18 00` |
| `SUCC` | mSuccess | `0e 00 10 00` |
| `BLID` | mPlayerId | `18 18 10 00` |
| `CONN` | mIsConnected | `0e 00 18 00` |
| `STOR` | mStory | `0a 00 10 00` |
| `BLID` | mNewsId | `0c 10 18 00` |
| `CLID` | mClubId | `17 18 10 00` |
| `ISHD` | mIsHidden | `0f 00 28 00` |
| `CLST` | mClubList | `02 18 10 00` |
| `CTCT` | mTotalCount | `15 00 68 00` |
| `AUTH` | mAuthCredentials | `0a 18 30 00` |
| `CAT ` | mCategoryName | `05 20 20 00` |
| `CTXT` | mContext | `05 00 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 30 00` |
| `CAT ` | mCategoryName | `05 20 20 00` |
| `CTXT` | mContext | `05 00 10 00` |
| `LIST` | mRecords | `02 18 10 00` |
| `TOTL` | mTotalCount | `15 00 68 00` |
| `PSCM` | mPosterComparisons | `01 18 10 00` |
| `USCM` | mUserComparisons | `01 00 60 00` |
| `PERM` | mPermissionByActionTypeMap | `01 00 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 30 01` |
| `CAT ` | mCategoryName | `05 20 20 00` |
| `CONF` | mConfiguration | `0a 18 80 00` |
| `CTXT` | mContext | `05 20 10 00` |
| `DESC` | mDescription | `05 20 30 00` |
| `TRST` | mTrustedSources | `02 00 40 00` |
| `BLID` | mBlazeId | `18 00 10 00` |
| `CLCN` | mClubsCount | `15 18 10 00` |
| `CLDM` | mClubsByDomain | `01 18 18 00` |
| `MBCN` | mMembersCount | `15 18 68 00` |
| `MBDM` | mMembersByDomain | `01 00 70 00` |
| `CLID` | mClubId | `17 18 18 00` |
| `UID ` | mUserId | `18 00 10 00` |
| `PARM` | mContentParams | `02 18 10 00` |
| `PRIO` | mPriority | `11 18 78 00` |
| `SPWL` | mSpeedwall | `05 20 80 00` |
| `SUBJ` | mSubject | `05 00 68 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `STTS` | mOverwatchStats | `01 00 18 00` |
| `TDF ` | mTdf | `06 00 10 00` |
| `CTXT` | mContext | `0a 18 18 00` |
| `RCRE` | mResourceCreated | `0e 00 10 00` |
| `RCID` | mRecordId | `15 18 10 00` |
| `RCNA` | mRecordName | `05 00 18 00` |

## (unnamed table @ 0x0001416b6ab0)

`0x0001416b6ab0` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `CIHA` | mCityHash | `17 18 30 00` |
| `GECI` | mGeoCity | `05 20 10 00` |
| `GECO` | mGeoCountry | `05 20 20 00` |
| `ISSE` | mIsSet | `0e 00 38 00` |

## (unnamed table @ 0x0001416b6b50)

`0x0001416b6b50` - 13 fields

| tag | field | meta |
| --- | --- | --- |
| `AMOA` | mWeaponAAmmo | `10 18 1c 01` |
| `AMOB` | mWeaponBAmmo | `10 18 1d 01` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `HEAL` | mHealthLevel | `10 18 19 01` |
| `NITR` | mNitrousLevel | `10 18 18 01` |
| `POSR` | mPosRList | `02 18 98 00` |
| `POSX` | mPosXList | `02 18 18 00` |
| `POSZ` | mPosZList | `02 18 58 00` |
| `STTE` | mGameStateField | `11 18 1e 01` |
| `TIMA` | mTimeAnimate | `14 18 20 01` |
| `TIML` | mTimestampList | `02 18 d8 00` |
| `WEPA` | mWeaponAId | `10 18 1a 01` |
| `WEPB` | mWeaponBId | `10 00 1b 01` |

## (unnamed table @ 0x0001416b6c88)

`0x0001416b6c88` - 8 fields

| tag | field | meta |
| --- | --- | --- |
| `CNOU` | mNumOfUsersByRegion | `01 00 10 00` |
| `CLID` | mRivalClubId | `17 18 10 00` |
| `COP1` | mCustOpt1 | `17 18 18 00` |
| `COP2` | mCustOpt2 | `17 18 20 00` |
| `COP3` | mCustOpt3 | `17 18 28 00` |
| `CRTI` | mCreationTime | `15 18 40 00` |
| `LATI` | mLastUpdateTime | `15 18 44 00` |
| `META` | mMetaData | `05 00 30 00` |

## (unnamed table @ 0x0001416b6d90)

`0x0001416b6d90` - 11 fields

| tag | field | meta |
| --- | --- | --- |
| `ADDR` | mRecordAddress | `0a 18 10 00` |
| `AUTH` | mAuthCredentials | `0a 00 70 00` |
| `AWST` | mAwardSettings | `02 18 18 00` |
| `CLDS` | mClubDivisionSize | `13 18 10 00` |
| `DMNS` | mDomainList | `02 18 d8 00` |
| `MXEV` | mMaxEvents | `13 18 c8 00` |
| `MXRV` | mMaxRivalsPerClub | `13 18 d4 00` |
| `PUHR` | mPurgeHour | `13 18 ca 00` |
| `REST` | mRecordSettings | `02 18 70 00` |
| `SOVR` | mSeasonRolloverTime | `14 18 cc 00` |
| `STRT` | mSeasonStartTime | `14 00 d0 00` |

## Blaze::ByteVault::User

`0x0001416b6e98` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `OTHR` | mOthers | `07 10 30 00` |
| `OWNR` | mOwner | `07 10 10 00` |
| `TRST` | mTrusted | `07 00 20 00` |
| `DSOO` | mDistanceToUnlockOverwatch | `14 18 14 00` |
| `DSPF` | mDistancePerFuel | `14 18 10 00` |
| `LVLS` | mLevelSpTargets | `02 00 18 00` |
| `CLIN` | mClubsComponentInfo | `0a 00 10 00` |

## (unnamed table @ 0x0001416b6f30)

`0x0001416b6f30` - 19 fields

| tag | field | meta |
| --- | --- | --- |
| `ADDR` | mRecordAddress | `0a 18 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 b0 00` |
| `LOAD` | mPayload | `0a 18 70 00` |
| `SUBR` | mSubrecordUpdate | `0e 00 a8 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `EVTS` | mEventIds | `02 18 60 00` |
| `FRND` | mFriendStory | `0e 18 18 00` |
| `GENS` | mGenerators | `02 18 20 00` |
| `USER` | mUserStory | `0e 00 19 00` |
| `CLST` | mClubList | `02 18 10 00` |
| `CTCT` | mTotalCount | `15 00 68 00` |
| `AVG ` | mAverageRecordSize | `17 18 20 00` |
| `IRAT` | mBytesIn | `17 18 10 00` |
| `MAX ` | mMaximumRecordSize | `17 18 30 00` |
| `MIN ` | mMinimumRecordSize | `17 18 28 00` |
| `NUMR` | mNumRecords | `15 18 38 00` |
| `ORAT` | mBytesOut | `17 00 18 00` |
| `NLMP` | mLocalizedNewsListMap | `01 18 10 00` |
| `TLPG` | mTotalPages | `13 00 78 00` |

## (unnamed table @ 0x0001416b7120)

`0x0001416b7120` - 10 fields

| tag | field | meta |
| --- | --- | --- |
| `ROWS` | mSpeedWall | `02 18 18 00` |
| `SWID` | mSpeedWallId | `15 00 10 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `DBG ` | mShowDebug | `0e 18 20 01` |
| `FLTP` | mFloatParamList | `02 18 a0 00` |
| `INTP` | mInt32ParamList | `02 18 20 00` |
| `MSTY` | mMessageId | `14 18 18 00` |
| `STRP` | mStringParamList | `02 18 e0 00` |
| `UINP` | mUint64ParamList | `02 00 60 00` |
| `ENTL` | mEntitlements | `01 00 10 00` |

## (unnamed table @ 0x0001416b7210)

`0x0001416b7210` - 15 fields

| tag | field | meta |
| --- | --- | --- |
| `DSOO` | mDistanceToUnlockOverwatch | `14 18 14 00` |
| `DSPF` | mDistancePerFuel | `14 18 10 00` |
| `LVLI` | mLevelSpId | `02 18 18 00` |
| `LVLS` | mLevelSpTargets | `02 00 58 00` |
| `CAT ` | mCategory | `0a 18 18 00` |
| `RCRE` | mResourceCreated | `0e 00 10 00` |
| `BILL` | mBillboardId | `15 18 18 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `BNTY` | mBounty | `14 00 1c 00` |
| `BLID` | mUserId | `18 18 18 00` |
| `CLID` | mClubId | `17 00 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 28 00` |
| `CTXT` | mContext | `05 20 10 00` |
| `MXRC` | mMaxResultCount | `15 18 20 00` |
| `OFFS` | mOffset | `15 00 24 00` |

## (unnamed table @ 0x0001416b73a8)

`0x0001416b73a8` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `BLID` | mBlazeId | `18 18 10 00` |
| `STTS` | mOverwatchStats | `01 00 18 00` |
| `AWID` | mAwardId | `15 18 10 00` |
| `AWIU` | mAwardImgURL | `05 20 18 00` |
| `CAWI` | mCount | `15 18 2c 00` |
| `IMCS` | mAwardImgCheckSum | `14 18 28 00` |
| `LUDT` | mLastUpdateTime | `15 00 30 00` |

## (unnamed table @ 0x0001416b7490)

`0x0001416b7490` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `RILI` | mRivalList | `02 18 78 00` |
| `SPWA` | mSpeedWallIDToSpeedWallMap | `01 00 10 00` |
| `CLID` | mClubId | `17 00 10 00` |
| `SUCC` | mMbSuccess | `0e 00 10 00` |

## (unnamed table @ 0x0001416b75d0)

`0x0001416b75d0` - 9 fields

| tag | field | meta |
| --- | --- | --- |
| `LOC ` | mLocation | `05 20 68 00` |
| `RCIN` | mRecord | `0a 18 10 00` |
| `RCRE` | mResourceCreated | `0e 18 60 00` |
| `RMOT` | mIsRemoteResource | `0e 00 78 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `GEN ` | mGenerator | `05 00 18 00` |
| `CONT` | mCount | `15 18 14 00` |
| `CTCT` | mTotalCount | `15 18 18 00` |
| `SQID` | mSequenceID | `15 00 10 00` |

## (unnamed table @ 0x0001416b76c0)

`0x0001416b76c0` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `BLID` | mBlazeId | `18 18 10 00` |
| `SWIS` | mSpeedWallIds | `02 18 18 00` |
| `USGE` | mUseGeoLocationUsers | `0e 18 59 00` |
| `USPG` | mUseSpecialGuests | `0e 00 58 00` |
| `BLID` | mUserId | `18 18 18 00` |
| `CLID` | mClubId | `17 00 10 00` |

## (unnamed table @ 0x0001416b7750)

`0x0001416b7750` - 10 fields

| tag | field | meta |
| --- | --- | --- |
| `ALLE` | mAllRecordsEditable | `0e 18 20 00` |
| `EDIT` | mEditableRecordNames | `02 18 28 00` |
| `PERM` | mAccessPermission | `0a 18 68 00` |
| `RCNT` | mMaxRecordsPerUser | `17 18 10 00` |
| `RSIZ` | mMaxRecordPayloadSize | `17 18 18 00` |
| `VERS` | mVersion | `15 00 a8 00` |
| `COMP` | mComparisons | `01 18 18 00` |
| `ENAB` | mEnabled | `0e 18 10 00` |
| `REPR` | mReports | `01 00 80 00` |
| `RESP` | mSuccess | `0e 00 10 00` |

## (unnamed table @ 0x0001416b7840)

`0x0001416b7840` - 13 fields

| tag | field | meta |
| --- | --- | --- |
| `MIME` | mContentType | `05 20 10 00` |
| `SDAT` | mBlob | `05 00 20 00` |
| `FRND` | mGenerateFriendStories | `0e 18 69 00` |
| `MTDF` | mVariableTdfs | `02 18 10 00` |
| `ONL ` | mUseOnlineStats | `0e 00 68 00` |
| `MSLI` | mMsgList | `02 00 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 38 00` |
| `CAT ` | mCategoryName | `05 20 20 00` |
| `CTXT` | mContext | `05 20 10 00` |
| `MXRC` | mMaxResultCount | `15 18 30 00` |
| `OFFS` | mOffset | `15 00 34 00` |
| `SUCC` | mMbSuccess | `0e 00 10 00` |
| `RESP` | mInGameRichPresenceResponseList | `02 00 10 00` |

## (unnamed table @ 0x0001416b7ab0)

`0x0001416b7ab0` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `BLID` | mBlazeId | `18 18 10 00` |
| `DBG ` | mShowDebug | `0e 18 2c 00` |
| `NMFR` | mNumFriends | `14 18 28 00` |
| `NMST` | mNumStrangers | `14 18 24 00` |
| `PRID` | mPresenceId | `14 18 18 00` |
| `RDID` | mRoadId | `14 18 20 00` |
| `VHID` | mVehicleId | `14 00 1c 00` |

## (unnamed table @ 0x0001416b7b58)

`0x0001416b7b58` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `SUCC` | mMbSuccess | `0e 00 10 00` |
| `ROAD` | mRoad | `15 18 10 00` |
| `ROWS` | mSpeedwall | `02 00 18 00` |

## (unnamed table @ 0x0001416b7bf8)

`0x0001416b7bf8` - 10 fields

| tag | field | meta |
| --- | --- | --- |
| `STTS` | mOverwatchStats | `01 18 18 00` |
| `SUCC` | mSuccess | `0e 00 10 00` |
| `BLIS` | mBlazeIDs | `02 00 10 00` |
| `CLUB` | mClub | `0a 18 18 00` |
| `SQID` | mSequenceID | `15 00 10 00` |
| `ROWS` | mSpeedwall | `02 00 10 00` |
| `BLID` | mUserId | `18 18 18 00` |
| `CLID` | mClubId | `17 00 10 00` |
| `RATE` | mDataRates | `0a 18 10 00` |
| `RATM` | mDataRatesPerCategoryPerContext | `01 00 50 00` |

## (unnamed table @ 0x0001416b7d20)

`0x0001416b7d20` - 8 fields

| tag | field | meta |
| --- | --- | --- |
| `ADDR` | mRecordAddress | `0a 18 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 80 00` |
| `SUBR` | mSubrecord | `05 00 70 00` |
| `CLID` | mClubId | `17 18 10 00` |
| `ISSU` | mIsSubscribed | `0f 00 18 00` |
| `MMAP` | mMembershipMap | `01 00 10 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `GLOB` | mGetGlobal | `0e 00 18 00` |

## (unnamed table @ 0x0001416b7e10)

`0x0001416b7e10` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `BLID` | mBlazeId | `18 18 10 00` |
| `DBG ` | mShowDebug | `0e 18 58 00` |
| `PLID` | mPlayerBlazeIdList | `02 00 18 00` |
| `BANS` | mUserIdToBanStatusMap | `01 00 10 00` |

## (unnamed table @ 0x0001416b7e70)

`0x0001416b7e70` - 8 fields

| tag | field | meta |
| --- | --- | --- |
| `CBD ` | mNumOfClubsByDomain | `01 18 b0 00` |
| `MBD ` | mNumOfClubMembersByDomain | `01 18 10 00` |
| `OCD ` | mNumOfOnlineClubsByDomain | `01 18 00 01` |
| `OCM ` | mNumOfOnlineClubMembers | `15 18 54 01` |
| `OMD ` | mNumOfOnlineClubMembersByDomain | `01 18 60 00` |
| `TCM ` | mNumOfClubMembers | `15 18 50 01` |
| `TNC ` | mNumOfClubs | `15 18 58 01` |
| `TOC ` | mNumOfOnlineClubs | `15 00 5c 01` |

## (unnamed table @ 0x0001416b7f70)

`0x0001416b7f70` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `LIST` | mRecords | `02 18 10 00` |
| `TOTL` | mTotalCount | `15 00 68 00` |
| `NMPA` | mStringMap | `01 18 28 00` |
| `NUM ` | mNum | `14 18 10 00` |
| `TEXT` | mText | `05 00 18 00` |
| `CBID` | mClubId | `17 18 10 00` |
| `USID` | mUserIds | `02 00 18 00` |

## (unnamed table @ 0x0001416b8050)

`0x0001416b8050` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `BLID` | mBlazeId | `18 18 10 00` |
| `PLSC` | mPlayerScore | `15 18 20 00` |
| `RIBL` | mRivalBlazeId | `18 18 18 00` |
| `RISC` | mRivalScore | `15 00 24 00` |

## (unnamed table @ 0x0001416b80b0)

`0x0001416b80b0` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `SUCC` | mSuccess | `0e 00 10 00` |
| `HOTS` | mHotRecommendationsData | `02 18 c0 00` |
| `STOR` | mStories | `02 18 10 00` |
| `WISD` | mWisdomOfCrowdsData | `02 00 68 00` |
| `CLID` | mClubId | `17 18 10 00` |
| `PSWD` | mPassword | `05 00 18 00` |

## (unnamed table @ 0x0001416b8150)

`0x0001416b8150` - 26 fields

| tag | field | meta |
| --- | --- | --- |
| `BEST` | mBlazeIdToPlayedAgainstStatus | `01 18 20 00` |
| `BLIS` | mBlazeId | `18 18 10 00` |
| `SWIS` | mSpeedWallId | `15 00 18 00` |
| `BLID` | mUserId | `18 18 18 00` |
| `CLID` | mClubId | `17 00 10 00` |
| `RIVL` | mClubRivalList | `02 00 10 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `DBG ` | mShowDebug | `0e 18 30 01` |
| `FCAP` | mFuelCap | `14 18 2c 01` |
| `FLTP` | mFloatParamList | `02 18 a8 00` |
| `FULS` | mFuelToSpend | `14 18 28 01` |
| `INTP` | mInt32ParamList | `02 18 28 00` |
| `MEID` | mMeBlazeId | `18 18 18 00` |
| `MSTY` | mMessageId | `14 18 20 00` |
| `STRP` | mStringParamList | `02 18 e8 00` |
| `UINP` | mUint64ParamList | `02 00 68 00` |
| `UID ` | mUserId | `18 00 10 00` |
| `BUST` | mBusts | `14 18 18 00` |
| `CBTY` | mCopBounty | `14 18 10 00` |
| `ESCP` | mEscapes | `14 18 1c 00` |
| `RBTY` | mRacerBounty | `14 00 14 00` |
| `CLID` | mClubId | `17 18 10 00` |
| `CTMS` | mMessage | `0a 18 38 00` |
| `EXUI` | mExcludeUserId | `18 18 20 00` |
| `INUI` | mIncludeUserId | `18 18 18 00` |
| `PRMS` | mParams | `05 00 28 00` |

## (unnamed table @ 0x0001416b8440)

`0x0001416b8440` - 10 fields

| tag | field | meta |
| --- | --- | --- |
| `GUID` | mResponseGUID | `05 20 18 00` |
| `SUCC` | mMbSuccess | `0e 00 10 00` |
| `LVLI` | mLevelId | `14 18 10 00` |
| `SPRQ` | mLevelSpRequired | `14 00 14 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `FUNA` | mFullName | `05 20 28 00` |
| `GUTY` | mGuestType | `05 00 18 00` |
| `AWRL` | mClubAwardList | `02 00 10 00` |
| `MOSM` | mStatus | `01 00 10 00` |
| `INID` | mInvitationId | `15 00 10 00` |

## (unnamed table @ 0x0001416b8580)

`0x0001416b8580` - 21 fields

| tag | field | meta |
| --- | --- | --- |
| `CAT ` | mCategoryName | `05 20 20 00` |
| `CTXT` | mContext | `05 20 10 00` |
| `OWNR` | mOwner | `0a 18 40 00` |
| `REC ` | mRecordName | `05 00 30 00` |
| `ROWS` | mSpeedwall | `02 00 10 00` |
| `BNTY` | mBountyTag | `14 18 e4 01` |
| `EVTG` | mEventTag | `15 18 d8 01` |
| `FRST` | mFriendStories | `02 18 80 01` |
| `PARM` | mParameters | `02 18 10 00` |
| `SPWL` | mSpeedwall | `0a 18 68 00` |
| `STOR` | mPosterStories | `02 18 28 01` |
| `TIME` | mTimeMsTag | `14 18 e0 01` |
| `VHTG` | mVehicleTag | `15 00 dc 01` |
| `ADMN` | mAdminEmail | `05 20 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 88 00` |
| `MAP ` | mAdminTypeListByContextMap | `01 00 20 00` |
| `BLIS` | mBlazeId | `18 18 10 00` |
| `SWIS` | mSpeedWallId | `15 00 18 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `DBG ` | mShowDebug | `0e 18 58 00` |
| `GETP` | mFriendBlazeIdList | `02 00 18 00` |

## (unnamed table @ 0x0001416b87a0)

`0x0001416b87a0` - 10 fields

| tag | field | meta |
| --- | --- | --- |
| `BLUS` | mBlazeUser | `0a 18 10 00` |
| `STAF` | mStatsFlt | `01 18 90 00` |
| `STAI` | mStatsInt | `01 18 40 00` |
| `STAS` | mStatsStr | `01 00 e0 00` |
| `MOSC` | mMemberOnlineStatusSum | `15 18 18 02` |
| `MOSL` | mMemberOnlineStatusFilter | `02 18 d8 01` |
| `RQST` | mParams | `0a 00 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 30 00` |
| `CAT ` | mCategoryName | `05 20 20 00` |
| `CTXT` | mContext | `05 00 10 00` |

## (unnamed table @ 0x0001416b8928)

`0x0001416b8928` - 9 fields

| tag | field | meta |
| --- | --- | --- |
| `BLIS` | mFriendRecommendations | `02 00 10 00` |
| `NLOS` | mLoss | `15 18 1c 00` |
| `NLUP` | mLastUpdateTime | `15 18 24 00` |
| `NTIE` | mTie | `15 18 20 00` |
| `NWIN` | mWin | `15 18 18 00` |
| `OPID` | mOppoClubId | `17 00 10 00` |
| `TIMD` | mMetadata | `05 20 20 00` |
| `TITX` | mText | `05 20 10 00` |
| `TSTM` | mTimestamp | `15 00 30 00` |

## (unnamed table @ 0x0001416b8a18)

`0x0001416b8a18` - 9 fields

| tag | field | meta |
| --- | --- | --- |
| `BLID` | mBlazeId | `18 18 10 00` |
| `ROWS` | mPlaylist | `02 00 18 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `ROWS` | mPlaylist | `02 00 18 00` |
| `SOVR` | mSeasonRolloverTime | `14 18 14 00` |
| `STRT` | mSeasonStartTime | `14 00 10 00` |
| `CBID` | mClubId | `17 18 50 00` |
| `URID` | mUserIds | `02 00 10 00` |
| `MOML` | mMsgListMap | `01 00 10 00` |

## (unnamed table @ 0x0001416b8b20)

`0x0001416b8b20` - 17 fields

| tag | field | meta |
| --- | --- | --- |
| `AWCN` | mAwardCount | `15 18 18 00` |
| `CIMC` | mMemberCount | `15 18 10 00` |
| `CRTI` | mCreationTime | `15 18 a0 00` |
| `GMCN` | mGmCount | `15 18 14 00` |
| `LATI` | mLastActiveTime | `15 18 a4 00` |
| `LGTM` | mLastGameTime | `15 18 48 00` |
| `LSGR` | mLastGameResult | `05 20 38 00` |
| `LSOP` | mLastOppo | `17 18 20 00` |
| `MSCO` | mMemberOnlineStatusCounts | `01 18 50 00` |
| `OPNM` | mLastOppoName | `05 20 28 00` |
| `RVCN` | mRivalCount | `15 00 a8 00` |
| `CDSC` | mDescription | `05 20 38 00` |
| `CLID` | mClubId | `17 18 10 00` |
| `CNAM` | mName | `05 20 18 00` |
| `NUQN` | mNonUniqueName | `05 00 28 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `REPO` | mTdf | `06 00 18 00` |

## (unnamed table @ 0x0001416b8d40)

`0x0001416b8d40` - 15 fields

| tag | field | meta |
| --- | --- | --- |
| `BLID` | mBlazeId | `18 18 10 00` |
| `GECI` | mGeoCity | `05 20 18 00` |
| `GECO` | mGeoCountry | `05 00 28 00` |
| `CLID` | mClubId | `17 18 10 00` |
| `NWLI` | mClubNews | `0a 00 18 00` |
| `DPSC` | mDeploySuccess | `0e 18 11 00` |
| `RESP` | mSuccess | `0e 18 10 00` |
| `STTS` | mOverwatchStats | `01 00 18 00` |
| `CIST` | mClubPetitionsList | `02 00 10 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `NMFR` | mNumFriends | `14 18 28 00` |
| `NMST` | mNumStrangers | `14 18 24 00` |
| `PRID` | mPresenceId | `14 18 18 00` |
| `RDID` | mRoadId | `14 18 20 00` |
| `VHID` | mVehicleId | `14 00 1c 00` |

## (unnamed table @ 0x0001416b8f00)

`0x0001416b8f00` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `COP1` | mCustOpt1 | `15 18 10 00` |
| `COP2` | mCustOpt2 | `15 18 14 00` |
| `COP3` | mCustOpt3 | `15 18 18 00` |
| `COP4` | mCustOpt4 | `15 18 1c 00` |
| `COP5` | mCustOpt5 | `15 00 20 00` |

## (unnamed table @ 0x0001416b8f78)

`0x0001416b8f78` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `BLID` | mBlazeId | `18 00 10 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `PLAY` | mPlaylistSimplified | `02 00 18 00` |

## (unnamed table @ 0x0001416b8fc0)

`0x0001416b8fc0` - 26 fields

| tag | field | meta |
| --- | --- | --- |
| `BLID` | mBlazeId | `18 18 10 00` |
| `PLAY` | mPlaylist | `02 00 18 00` |
| `CLID` | mClubId | `17 18 10 00` |
| `TSTM` | mOldestTimestamp | `15 00 18 00` |
| `MSSS` | mStatus | `01 00 10 00` |
| `LICE` | mResult | `05 20 18 00` |
| `SUCC` | mMbSuccess | `0e 00 10 00` |
| `ATMP` | mAttempts | `13 18 28 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `BNTY` | mBounty | `14 18 1c 00` |
| `MODC` | mModsCount | `15 18 30 00` |
| `MODU` | mModsUsed | `15 18 2c 00` |
| `PLAY` | mNumPlayers | `11 18 34 00` |
| `PRPO` | mProgressionPosition | `11 18 2a 00` |
| `TIME` | mTimeMs | `14 18 18 00` |
| `VEHI` | mVehicle | `15 18 20 00` |
| `WIN ` | mWin | `15 00 24 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `TIME` | mTimeMs | `14 18 18 00` |
| `UPDT` | mUpdatedTimestamp | `15 18 20 00` |
| `VEHI` | mVehicle | `15 00 1c 00` |
| `NLST` | mBeatYouNotifications | `02 00 10 00` |
| `SCRS` | mScores | `02 00 10 00` |
| `CLRL` | mClubRecordList | `02 00 10 00` |
| `ROWS` | mSpeedwall | `02 00 10 00` |
| `CIST` | mClubInvList | `02 00 10 00` |

## (unnamed table @ 0x0001416b9278)

`0x0001416b9278` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `SUCC` | mMbSuccess | `0e 00 10 00` |
| `RATM` | mErrorsPerCategoryPerContext | `01 00 10 00` |
| `INID` | mPetitionId | `15 00 10 00` |

## (unnamed table @ 0x0001416b92c0)

`0x0001416b92c0` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `BLID` | mBlazeId | `18 18 10 00` |
| `FRID` | mFriendBlazeId | `18 00 18 00` |
| `CLTG` | mTagList | `02 18 30 01` |
| `CNAM` | mName | `05 20 18 00` |
| `CSET` | mClubSettings | `0a 18 28 00` |
| `DMID` | mClubDomainId | `15 00 10 00` |

## (unnamed table @ 0x0001416b9380)

`0x0001416b9380` - 8 fields

| tag | field | meta |
| --- | --- | --- |
| `ADDR` | mRecordAddress | `0a 18 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 78 00` |
| `MXRC` | mMaxResultCount | `15 18 70 00` |
| `OFFS` | mOffset | `15 00 74 00` |
| `CLID` | mClubId | `17 18 10 00` |
| `META` | mMetaData | `01 00 18 00` |
| `CLID` | mClubId | `17 18 10 00` |
| `WIPS` | mWipeSet | `05 00 18 00` |

## (unnamed table @ 0x0001416b94a0)

`0x0001416b94a0` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `CLID` | mClubId | `17 18 10 00` |
| `CLIN` | mClubInfo | `0a 18 38 01` |
| `CLST` | mClubSettings | `0a 18 30 00` |
| `CLTG` | mTagList | `02 18 e8 01` |
| `DMID` | mClubDomainId | `15 18 28 00` |
| `NAME` | mName | `05 00 18 00` |
| `MCMP` | mCountMap | `01 00 10 00` |

## (unnamed table @ 0x0001416b9550)

`0x0001416b9550` - 13 fields

| tag | field | meta |
| --- | --- | --- |
| `ISSP` | mIsItemSpecial | `0e 18 1c 00` |
| `MEDL` | mTargetMedal | `14 18 20 00` |
| `RWCU` | mRewardCarId | `15 18 34 00` |
| `RWFU` | mRewardOverwatchFuel | `15 18 30 00` |
| `RWLU` | mRewardCarLivery | `15 18 38 00` |
| `RWOP` | mRewardOverwatchSp | `15 18 2c 00` |
| `RWSP` | mRewardSp | `15 18 28 00` |
| `SCID` | mItemScopeValue | `15 18 14 00` |
| `SPID` | mSpecialEventId | `15 18 3c 00` |
| `TIMA` | mTimeItemAdded | `15 18 18 00` |
| `TIMX` | mTimeItemExpires | `15 18 24 00` |
| `TYPE` | mItemType | `11 00 10 00` |
| `SID ` | mServerId | `15 00 10 00` |

## (unnamed table @ 0x0001416c39f0)

`0x0001416c39f0` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `AGKY` | mAggregateKeyValue | `16 18 68 00` |
| `ENAG` | mEnableAggregation | `0f 18 60 00` |
| `KSVL` | mKeyScopeValues | `01 00 10 00` |
| `CNT ` | mCount | `14 00 10 00` |
| `BURL` | mBannerUrl | `05 20 18 00` |
| `CLR ` | mClearBannerUrl | `0e 18 28 00` |
| `SID ` | mServerId | `15 00 10 00` |

## (unnamed table @ 0x0001416c3aa0)

`0x0001416c3aa0` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `ADRS` | mAddress | `05 20 10 00` |
| `PORT` | mPort | `15 18 20 00` |
| `SKEY` | mKey | `05 00 28 00` |
| `CTID` | mCategoryId | `17 00 10 00` |
| `CODE` | mResultCode | `13 18 10 00` |
| `OFFS` | mOffendingString | `05 00 18 00` |

## (unnamed table @ 0x0001416c3b50)

`0x0001416c3b50` - 35 fields

| tag | field | meta |
| --- | --- | --- |
| `PSS ` | mPssConfig | `0a 18 10 00` |
| `TELE` | mTelemetryServer | `0a 18 a0 00` |
| `TICK` | mTickerServer | `0a 18 58 01` |
| `UROP` | mUserOptions | `0a 00 90 01` |
| `GID ` | mGameId | `17 00 10 00` |
| `KEY ` | mKey | `05 20 10 00` |
| `MAX ` | mMax | `12 18 22 00` |
| `MIN ` | mMin | `12 00 20 00` |
| `DBUF` | mDailyBuffer | `14 18 24 00` |
| `DHOU` | mDailyHour | `14 18 1c 00` |
| `DLY ` | mCurrentDailyPeriodId | `14 18 10 00` |
| `DRET` | mDailyRetention | `14 18 20 00` |
| `MBUF` | mMonthlyBuffer | `14 18 44 00` |
| `MDAY` | mMonthlyDay | `14 18 3c 00` |
| `MHOU` | mMonthlyHour | `14 18 38 00` |
| `MLY ` | mCurrentMonthlyPeriodId | `14 18 18 00` |
| `MRET` | mMonthlyRetention | `14 18 40 00` |
| `WBUF` | mWeeklyBuffer | `14 18 34 00` |
| `WDAY` | mWeeklyDay | `14 18 2c 00` |
| `WHOU` | mWeeklyHour | `14 18 28 00` |
| `WLY ` | mCurrentWeeklyPeriodId | `14 18 14 00` |
| `WRET` | mWeeklyRetention | `14 00 30 00` |
| `IEXP` | mIncludeExpired | `0e 18 20 00` |
| `PSAL` | mPingSiteAlias | `05 00 10 00` |
| `ATTR` | mAttributeMap | `01 00 10 00` |
| `MAP ` | mMap | `05 20 20 00` |
| `MODE` | mGameMode | `05 00 10 00` |
| `SETT` | mServerSettings | `0a 18 18 00` |
| `SID ` | mServerId | `15 00 10 00` |
| `NAME` | mName | `05 20 10 00` |
| `TYPE` | mUpdateType | `14 18 30 00` |
| `VALU` | mValue | `05 00 20 00` |
| `CDAT` | mCategoryData | `0a 18 a0 01` |
| `MDAT` | mMemberData | `0a 18 a8 03` |
| `RDAT` | mRoomData | `0a 00 20 03` |

## (unnamed table @ 0x0001416c3ed8)

`0x0001416c3ed8` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `LDLS` | mRows | `02 00 10 00` |
| `MID ` | mMatchId | `17 18 28 00` |
| `PGID` | mPersistedGameId | `05 20 18 00` |
| `UID ` | mAdminUserId | `18 00 10 00` |

## (unnamed table @ 0x0001416c3f40)

`0x0001416c3f40` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `CMAC` | mMacAddress | `05 20 10 00` |
| `SNAM` | mServiceName | `05 00 20 00` |

## (unnamed table @ 0x0001416c3f80)

`0x0001416c3f80` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `DATA` | mData | `05 20 20 00` |
| `KEY ` | mKey | `05 00 10 00` |

## (unnamed table @ 0x0001416c3fc0)

`0x0001416c3fc0` - 15 fields

| tag | field | meta |
| --- | --- | --- |
| `DISP` | mDisplayName | `05 20 20 00` |
| `GMET` | mGameMetaData | `01 18 88 00` |
| `META` | mClientMetaData | `01 18 38 00` |
| `MXRM` | mMaxUserRooms | `15 18 30 00` |
| `NAME` | mName | `05 20 10 00` |
| `USRM` | mNumUserRooms | `15 18 e0 00` |
| `VWID` | mViewId | `17 00 d8 00` |
| `CID ` | mCategoryId | `13 18 10 00` |
| `NAME` | mName | `05 00 18 00` |
| `HIST` | mIncludeHistory | `0e 18 19 00` |
| `IADM` | mIncludeAdminServers | `0e 18 18 00` |
| `UID ` | mUserId | `18 00 10 00` |
| `PRES` | mPreset | `0a 18 18 00` |
| `SID ` | mServerId | `15 00 10 00` |
| `RMSL` | mRoomDataList | `02 00 10 00` |

## (unnamed table @ 0x0001416c4148)

`0x0001416c4148` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `STIM` | mServerTime | `15 00 10 00` |
| `PGID` | mPersistedGameId | `05 00 10 00` |
| `VMAP` | mSpecMap | `01 00 10 00` |

## (unnamed table @ 0x0001416c4198)

`0x0001416c4198` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `KEY ` | mKey | `05 20 18 00` |
| `UID ` | mUserId | `18 00 10 00` |

## (unnamed table @ 0x0001416c41d8)

`0x0001416c41d8` - 10 fields

| tag | field | meta |
| --- | --- | --- |
| `TLST` | mFilteredTextList | `02 00 10 00` |
| `ATTR` | mRoomAttributes | `01 18 40 00` |
| `CRIT` | mEntryCriteria | `01 18 90 00` |
| `CTID` | mCategoryId | `17 18 28 00` |
| `PASS` | mPassword | `05 20 30 00` |
| `RCAP` | mCapacity | `14 18 20 00` |
| `RNAM` | mName | `05 20 10 00` |
| `USET` | mUserSetId | `0c 00 e0 00` |
| `POPA` | mPopulationAttributes | `01 18 60 00` |
| `POPM` | mPopulation | `01 00 10 00` |

## (unnamed table @ 0x0001416c4310)

`0x0001416c4310` - 10 fields

| tag | field | meta |
| --- | --- | --- |
| `AGGR` | mEntityAggrList | `02 18 68 00` |
| `STAT` | mEntityStatsList | `02 00 10 00` |
| `RMID` | mRoomId | `17 00 10 00` |
| `MAPR` | mMapRotation | `0a 18 18 00` |
| `SID ` | mServerId | `15 00 10 00` |
| `RMID` | mRoomId | `17 00 10 00` |
| `CID ` | mCategoryId | `13 18 40 00` |
| `DESC` | mDescription | `05 20 30 00` |
| `KEY ` | mKey | `05 20 10 00` |
| `NAME` | mName | `05 00 20 00` |

## (unnamed table @ 0x0001416c4418)

`0x0001416c4418` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `ACC ` | mAccept | `05 20 10 00` |
| `SIR ` | mRequest | `0a 00 20 00` |

## Blaze::Util::UserText

`0x0001416c4450` - 10 fields

| tag | field | meta |
| --- | --- | --- |
| `BOTT` | mShowAtBottomIfNotFound | `0e 18 a8 00` |
| `CENT` | mCenter | `1b 18 30 00` |
| `COUN` | mCount | `14 18 38 00` |
| `KSUM` | mKeyScopeNameValueMap | `01 18 40 00` |
| `LBID` | mBoardId | `14 18 20 00` |
| `NAME` | mBoardName | `05 20 10 00` |
| `POFF` | mPeriodOffset | `14 18 28 00` |
| `PRID` | mPeriodId | `14 18 24 00` |
| `TIME` | mTime | `14 18 90 00` |
| `USET` | mUserSetId | `0c 00 98 00` |

## (unnamed table @ 0x0001416c45a0)

`0x0001416c45a0` - 11 fields

| tag | field | meta |
| --- | --- | --- |
| `CDAT` | mClientData | `0a 18 a0 00` |
| `CINF` | mClientInfo | `0a 18 10 00` |
| `FCCR` | mFetchClientConfig | `0a 00 d0 00` |
| `ACTV` | mIsActive | `0f 00 10 00` |
| `FLDS` | mFolderDescriptors | `02 18 58 00` |
| `META` | mMetadata | `05 20 48 00` |
| `OWDS` | mDescription | `05 20 28 00` |
| `OWID` | mFolderId | `15 18 14 00` |
| `OWNM` | mName | `05 20 18 00` |
| `PRID` | mParentId | `15 18 10 00` |
| `SDES` | mShortDesc | `05 00 38 00` |

## (unnamed table @ 0x0001416c46d0)

`0x0001416c46d0` - 11 fields

| tag | field | meta |
| --- | --- | --- |
| `DATA` | mData | `05 20 28 00` |
| `KEY ` | mKey | `05 20 18 00` |
| `UID ` | mUserId | `18 00 10 00` |
| `CMAP` | mSpecMap | `01 00 10 00` |
| `BLST` | mBannedList | `02 00 10 00` |
| `SID ` | mServerId | `15 18 10 00` |
| `UID ` | mUserId | `18 00 18 00` |
| `RMID` | mRoomId | `17 00 10 00` |
| `ENBL` | mReceiveNotifications | `0f 00 10 00` |
| `VWID` | mViewId | `17 00 10 00` |
| `UID ` | mUserId | `18 00 10 00` |

## (unnamed table @ 0x0001416c47f0)

`0x0001416c47f0` - 21 fields

| tag | field | meta |
| --- | --- | --- |
| `CAPA` | mCapacity | `15 18 70 00` |
| `CMET` | mClientMetaData | `01 18 f0 00` |
| `CRIT` | mEntryCriteria | `01 18 a0 00` |
| `CTID` | mCategoryId | `17 18 10 00` |
| `DESC` | mDescription | `05 20 50 00` |
| `DISP` | mDisplayName | `05 20 30 00` |
| `DISR` | mRoomDisplayName | `05 20 40 00` |
| `EMAX` | mMaxExpandedRooms | `15 18 7c 00` |
| `EPCT` | mExpandThresholdPercent | `13 18 76 00` |
| `FLAG` | mFlags | `07 10 90 00` |
| `GMET` | mGameMetaData | `01 18 40 01` |
| `LOCL` | mLocale | `05 20 80 00` |
| `NAME` | mName | `05 20 20 00` |
| `NEXP` | mNumExpandedRooms | `13 18 78 00` |
| `PASS` | mPassword | `05 20 60 00` |
| `UCRT` | mIsUserCreated | `0f 18 74 00` |
| `VWID` | mViewId | `17 00 18 00` |
| `CDAT` | mCategoryData | `0a 18 90 02` |
| `MDAT` | mMemberData | `0a 18 98 04` |
| `RDAT` | mRoomData | `0a 18 10 04` |
| `VDAT` | mViewData | `0a 00 f8 00` |

## (unnamed table @ 0x0001416c4a10)

`0x0001416c4a10` - 33 fields

| tag | field | meta |
| --- | --- | --- |
| `CNAM` | mCategoryName | `05 20 30 00` |
| `DESC` | mDesc | `05 20 20 00` |
| `ETYP` | mEntityType | `0b 10 40 00` |
| `KSUM` | mKeyScopeNameValueMap | `01 18 b0 00` |
| `META` | mMetadata | `05 20 48 00` |
| `NAME` | mName | `05 20 10 00` |
| `STAT` | mStatDescs | `02 00 58 00` |
| `ALST` | mAdminList | `02 18 e0 01` |
| `BLST` | mBanList | `02 18 20 02` |
| `MLST` | mMapRotations | `02 18 88 01` |
| `PLST` | mPresets | `02 18 30 01` |
| `SERV` | mServer | `0a 18 10 00` |
| `SETT` | mServerSettings | `0a 18 c0 00` |
| `VLST` | mVipList | `02 00 60 02` |
| `UID ` | mUserId | `18 00 10 00` |
| `RMID` | mRoomId | `17 00 10 00` |
| `DESC` | mDesc | `05 20 20 00` |
| `KSUM` | mKeyScopeNameValueMap | `01 18 40 00` |
| `META` | mMetadata | `05 20 30 00` |
| `NAME` | mName | `05 00 10 00` |
| `FLID` | mFolderId | `15 18 20 00` |
| `NAME` | mFolderName | `05 00 10 00` |
| `BANU` | mBanUser | `0f 18 20 00` |
| `MBID` | mUserId | `18 18 18 00` |
| `RMID` | mRoomId | `17 00 10 00` |
| `MBID` | mUserId | `18 18 10 00` |
| `RMID` | mRoomId | `17 00 18 00` |
| `FCRI` | mFailedCriteria | `05 20 10 00` |
| `PASS` | mPassed | `0f 00 20 00` |
| `CNTX` | mContext | `13 18 20 00` |
| `SID ` | mServerId | `15 18 10 00` |
| `UID ` | mUserId | `18 00 18 00` |
| `UPDT` | mUpdates | `15 00 10 00` |

## (unnamed table @ 0x0001416c4d70)

`0x0001416c4d70` - 10 fields

| tag | field | meta |
| --- | --- | --- |
| `ASCD` | mAscending | `0f 18 2c 01` |
| `BNAM` | mBoardName | `05 20 38 00` |
| `DESC` | mDesc | `05 20 48 00` |
| `ETYP` | mEntityType | `0b 10 10 00` |
| `KSUM` | mKeyScopeNameValueListMap | `01 18 c0 00` |
| `LBSZ` | mLeaderboardSize | `14 18 28 01` |
| `LIST` | mStatKeyColumns | `02 18 68 00` |
| `META` | mMetadata | `05 20 58 00` |
| `NAME` | mName | `05 20 28 00` |
| `SNAM` | mStatName | `05 00 18 00` |

## (unnamed table @ 0x0001416c4e80)

`0x0001416c4e80` - 11 fields

| tag | field | meta |
| --- | --- | --- |
| `ENAM` | mEntityName | `05 20 40 00` |
| `ENID` | mEntityId | `1b 18 18 00` |
| `EXBL` | mExternalBlob | `08 10 28 00` |
| `EXID` | mExternalId | `17 18 20 00` |
| `RANK` | mRank | `14 18 10 00` |
| `RSTA` | mRankedStat | `05 20 58 00` |
| `RWFG` | mIsRawStats | `0e 18 a8 00` |
| `RWOT` | mOtherRawStats | `02 18 d8 00` |
| `RWST` | mRankedRawStat | `09 10 b0 00` |
| `STAT` | mOtherStats | `02 18 68 00` |
| `UATT` | mAttribute | `17 00 50 00` |

## (unnamed table @ 0x0001416c4f90)

`0x0001416c4f90` - 31 fields

| tag | field | meta |
| --- | --- | --- |
| `FILT` | mIncludeStatlessEntities | `0f 18 d8 00` |
| `IDLS` | mListOfIds | `02 18 30 00` |
| `KSUM` | mKeyScopeNameValueMap | `01 18 70 00` |
| `LBID` | mBoardId | `14 18 20 00` |
| `LIMT` | mLimit | `15 18 dc 00` |
| `NAME` | mBoardName | `05 20 10 00` |
| `POFF` | mPeriodOffset | `14 18 28 00` |
| `PRID` | mPeriodId | `14 18 24 00` |
| `TIME` | mTime | `14 18 c0 00` |
| `USET` | mUserSetId | `0c 00 c8 00` |
| `CTID` | mCategoryId | `17 18 10 00` |
| `RMID` | mRoomId | `17 00 18 00` |
| `SMAP` | mDataMap | `01 00 10 00` |
| `GID ` | mGameId | `17 00 10 00` |
| `RMID` | mRoomId | `17 18 10 00` |
| `USID` | mUserId | `18 00 18 00` |
| `CAT ` | mCategory | `05 20 10 00` |
| `STAT` | mStatNames | `02 00 20 00` |
| `VWID` | mViewId | `17 00 10 00` |
| `MBID` | mUserId | `18 18 10 00` |
| `RMID` | mRoomId | `17 00 18 00` |
| `CTID` | mCategoryId | `17 18 10 00` |
| `PVAL` | mPseudoValue | `05 00 18 00` |
| `LOC ` | mLocale | `15 18 50 00` |
| `RMID` | mRoomIdList | `02 00 10 00` |
| `CNTX` | mContext | `13 18 20 00` |
| `GID ` | mGameId | `17 18 10 00` |
| `UID ` | mUserId | `18 00 18 00` |
| `KEY ` | mKey | `05 20 18 00` |
| `UID ` | mUserId | `18 00 10 00` |
| `CTID` | mCategoryId | `17 00 10 00` |

## (unnamed table @ 0x0001416c52a0)

`0x0001416c52a0` - 9 fields

| tag | field | meta |
| --- | --- | --- |
| `COUN` | mCount | `14 18 30 00` |
| `KSUM` | mKeyScopeNameValueMap | `01 18 38 00` |
| `LBID` | mBoardId | `14 18 20 00` |
| `NAME` | mBoardName | `05 20 10 00` |
| `POFF` | mPeriodOffset | `14 18 28 00` |
| `PRID` | mPeriodId | `14 18 24 00` |
| `STRT` | mRankStart | `14 18 2c 00` |
| `TIME` | mTime | `14 18 88 00` |
| `USET` | mUserSetId | `0c 00 90 00` |

## (unnamed table @ 0x0001416c5378)

`0x0001416c5378` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `CFID` | mConfigSection | `05 00 10 00` |

## (unnamed table @ 0x0001416c5398)

`0x0001416c5398` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `UTXT` | mTextList | `02 00 10 00` |
| `ETYP` | mEntityType | `0b 10 10 00` |
| `STAT` | mStatDescs | `02 00 18 00` |

## (unnamed table @ 0x0001416c53e0)

`0x0001416c53e0` - 17 fields

| tag | field | meta |
| --- | --- | --- |
| `CATG` | mCategory | `05 20 88 00` |
| `DFLT` | mDefaultValue | `05 20 48 00` |
| `DRVD` | mDerived | `0f 18 98 00` |
| `FRMT` | mFormat | `05 20 58 00` |
| `KIND` | mKind | `05 20 68 00` |
| `LDSC` | mLongDesc | `05 20 30 00` |
| `META` | mMetadata | `05 20 78 00` |
| `NAME` | mName | `05 20 10 00` |
| `SDSC` | mShortDesc | `05 20 20 00` |
| `TYPE` | mType | `14 00 40 00` |
| `ATTR` | mRoomAttributes | `01 18 18 00` |
| `RMID` | mRoomId | `17 00 10 00` |
| `FLDS` | mDescription | `05 20 28 00` |
| `FLID` | mFolderId | `15 18 10 00` |
| `FLNM` | mName | `05 20 18 00` |
| `SDES` | mShortDesc | `05 00 38 00` |
| `GRPS` | mGroups | `02 00 10 00` |

## (unnamed table @ 0x0001416c55d0)

`0x0001416c55d0` - 26 fields

| tag | field | meta |
| --- | --- | --- |
| `GRNM` | mGroupName | `05 20 18 00` |
| `KEY ` | mKeyString | `05 20 28 00` |
| `LAST` | mLast | `0f 18 38 00` |
| `STS ` | mStatValues | `0a 18 40 00` |
| `VID ` | mViewId | `15 00 10 00` |
| `MBID` | mUserId | `18 18 10 00` |
| `RMID` | mRoomId | `17 00 18 00` |
| `UPDT` | mStatUpdates | `02 00 10 00` |
| `ALIA` | mAlias | `05 20 10 00` |
| `CAP ` | mCapacity | `15 18 30 00` |
| `NAME` | mName | `05 00 20 00` |
| `CATS` | mCategoryData | `0a 18 10 00` |
| `DURA` | mDuration | `15 18 a4 01` |
| `RECU` | mRecurrence | `15 18 a8 01` |
| `STAR` | mStart | `15 00 a0 01` |
| `SID ` | mServerId | `15 18 10 00` |
| `UID ` | mUserId | `18 00 18 00` |
| `CTID` | mCategoryId | `17 18 18 00` |
| `INID` | mInviterId | `18 18 48 00` |
| `INVT` | mIsUserInvited | `0f 18 30 00` |
| `PASS` | mPassword | `05 20 20 00` |
| `PVAL` | mPseudoValue | `05 20 38 00` |
| `RMID` | mRoomId | `17 18 10 00` |
| `USET` | mUserSetId | `0c 00 50 00` |
| `BZID` | mUserId | `18 18 10 00` |
| `RMID` | mRoomId | `17 00 18 00` |

## (unnamed table @ 0x0001416c5870)

`0x0001416c5870` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `CONF` | mConfig | `01 00 60 00` |

## (unnamed table @ 0x0001416c5890)

`0x0001416c5890` - 18 fields

| tag | field | meta |
| --- | --- | --- |
| `AREM` | mAutoRemove | `0f 18 2c 01` |
| `ATTR` | mAttributes | `01 18 88 00` |
| `BLST` | mBannedUsers | `02 18 38 01` |
| `CAP ` | mCapacity | `14 18 54 00` |
| `CNAM` | mCreatorPersonaName | `05 20 40 00` |
| `CRET` | mCreatorUserId | `18 18 38 00` |
| `CRIT` | mEntryCriteria | `01 18 d8 00` |
| `CRTM` | mCreationTime | `15 18 30 01` |
| `CTID` | mCategoryId | `17 18 18 00` |
| `ENUM` | mRoomNumber | `15 18 28 01` |
| `HNAM` | mHostPersonaName | `05 20 28 00` |
| `HOST` | mHostUserId | `18 18 20 00` |
| `NAME` | mName | `05 20 68 00` |
| `POPU` | mPopulation | `15 18 50 00` |
| `PSWD` | mPassword | `05 20 78 00` |
| `PVAL` | mPseudoValue | `05 20 58 00` |
| `RMID` | mRoomId | `17 18 10 00` |
| `UCRT` | mIsUserCreated | `0f 00 2d 01` |

## (unnamed table @ 0x0001416c5a68)

`0x0001416c5a68` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `KSIT` | mKeyScopesMap | `01 00 78 00` |
| `ATTR` | mMemberAttributes | `01 18 20 00` |
| `EID ` | mBlazeId | `18 18 18 00` |
| `RMID` | mRoomId | `17 00 10 00` |

## (unnamed table @ 0x0001416c5ac8)

`0x0001416c5ac8` - 11 fields

| tag | field | meta |
| --- | --- | --- |
| `NAME` | mName | `05 00 10 00` |
| `GID ` | mGameId | `17 18 18 00` |
| `PGID` | mPersistedGameId | `05 20 20 00` |
| `SID ` | mServerId | `15 00 10 00` |
| `NAME` | mFolderName | `05 00 10 00` |
| `CDAT` | mCategoryData | `0a 18 f8 00` |
| `MDAT` | mMemberData | `0a 18 80 04` |
| `RDAT` | mRoomData | `0a 18 88 02` |
| `VDAT` | mViewData | `0a 00 10 00` |
| `SCHS` | mScheduledSpec | `0a 18 18 00` |
| `SOID` | mScheduledId | `15 00 10 00` |

## (unnamed table @ 0x0001416c5c70)

`0x0001416c5c70` - 10 fields

| tag | field | meta |
| --- | --- | --- |
| `AGGR` | mAggrFlags | `07 10 c8 00` |
| `EID ` | mEntityIds | `02 18 20 00` |
| `KSUM` | mKeyScopeNameValueMap | `01 18 70 00` |
| `NAME` | mGroupName | `05 20 10 00` |
| `PCTR` | mPeriodCtr | `14 18 6c 00` |
| `POFF` | mPeriodOffset | `14 18 68 00` |
| `PRID` | mPeriodId | `14 18 64 00` |
| `PTYP` | mPeriodType | `14 18 60 00` |
| `TIME` | mTime | `14 18 d8 00` |
| `VID ` | mViewId | `15 00 c0 00` |

## (unnamed table @ 0x0001416c5d60)

`0x0001416c5d60` - 14 fields

| tag | field | meta |
| --- | --- | --- |
| `EID ` | mEntityId | `1b 18 10 00` |
| `ETYP` | mEntityType | `0b 10 18 00` |
| `POFF` | mPeriodOffset | `14 18 1c 00` |
| `STAT` | mStatValues | `02 00 20 00` |
| `LANG` | mLocale | `15 18 50 00` |
| `LSID` | mStringIds | `02 00 10 00` |
| `CTID` | mCategoryId | `17 00 10 00` |
| `CDAT` | mCategoryData | `0a 18 00 01` |
| `CRIT` | mFailedCriteria | `05 20 08 04` |
| `MDAT` | mMemberData | `0a 18 98 04` |
| `RDAT` | mRoomData | `0a 18 90 02` |
| `VDAT` | mViewData | `0a 18 18 00` |
| `VERS` | mMapVersion | `17 00 10 00` |
| `SOID` | mScheduledId | `15 00 10 00` |

## (unnamed table @ 0x0001416c5eb0)

`0x0001416c5eb0` - 9 fields

| tag | field | meta |
| --- | --- | --- |
| `ADRS` | mAddress | `05 20 10 00` |
| `AMAX` | mMaxAchievEnumSize | `15 18 8c 00` |
| `OIDS` | mOfferIds | `02 18 48 00` |
| `OMAX` | mMaxOfferEnumSize | `15 18 88 00` |
| `PJID` | mProjectId | `05 20 28 00` |
| `PORT` | mPort | `15 18 20 00` |
| `RPRT` | mInitialReportTypes | `07 10 38 00` |
| `TIID` | mTitleId | `15 00 24 00` |
| `ERKM` | mEntityRankMap | `01 00 10 00` |

## (unnamed table @ 0x0001416c6070)

`0x0001416c6070` - 13 fields

| tag | field | meta |
| --- | --- | --- |
| `CHDE` | mNext2Last | `15 18 3c 00` |
| `CHDS` | mFirstChild | `15 18 38 00` |
| `LAST` | mLastNode | `0f 18 40 00` |
| `NAME` | mNodeName | `05 20 18 00` |
| `NDID` | mNodeId | `15 18 10 00` |
| `RTNM` | mRootName | `05 20 48 00` |
| `SDES` | mShortDesc | `05 00 28 00` |
| `SID ` | mServerId | `15 00 10 00` |
| `STRM` | mVerifyStringResult | `02 00 10 00` |
| `053 ` | mLanguage | `01 00 00 00` |
| `ATTR` | mAttributes | `01 18 18 00` |
| `CTID` | mCategoryId | `17 00 10 00` |
| `SMAP` | mLocalizedStrings | `01 00 10 00` |

## (unnamed table @ 0x0001416c6308)

`0x0001416c6308` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `LBID` | mBoardId | `14 18 20 00` |
| `NAME` | mBoardName | `05 00 10 00` |

## (unnamed table @ 0x0001416c6440)

`0x0001416c6440` - 15 fields

| tag | field | meta |
| --- | --- | --- |
| `ASRC` | mAuthenticationSource | `05 20 b8 01` |
| `CIDS` | mComponentIds | `02 18 40 00` |
| `CONF` | mConfig | `0a 18 80 00` |
| `ESRC` | mEntitlementSource | `05 20 f0 01` |
| `INST` | mInstanceName | `05 20 30 00` |
| `MINR` | mUnderageSupported | `0e 18 e8 01` |
| `NASP` | mPersonaNamespace | `05 20 a8 01` |
| `PILD` | mLegalDocGameIdentifier | `05 20 d8 01` |
| `PLAT` | mPlatform | `05 20 20 00` |
| `QOSS` | mQosSettings | `0a 18 e8 00` |
| `RSRC` | mRegistrationSource | `05 20 c8 01` |
| `SVER` | mServerVersion | `05 00 10 00` |
| `RMID` | mRoomId | `17 18 10 00` |
| `USET` | mUserSetId | `0c 00 18 00` |
| `053 ` | mLanguage | `01 00 00 00` |

## (unnamed table @ 0x0001416c6790)

`0x0001416c6790` - 9 fields

| tag | field | meta |
| --- | --- | --- |
| `ATTR` | mMemberAttributes | `01 18 20 00` |
| `BZID` | mBlazeId | `18 18 10 00` |
| `RMID` | mRoomId | `17 18 18 00` |
| `USET` | mUserSetId | `0c 00 70 00` |
| `CAT ` | mCategory | `05 20 10 00` |
| `POFF` | mPeriodOffset | `14 18 28 00` |
| `PRID` | mPeriodId | `14 18 24 00` |
| `PTYP` | mPeriodType | `14 00 20 00` |
| `CATS` | mCategories | `02 00 10 00` |

## (unnamed table @ 0x0001416c6c70)

`0x0001416c6c70` - 42 fields

| tag | field | meta |
| --- | --- | --- |
| `UTXT` | mText | `05 00 10 00` |
| `ATTR` | mRoomAttributes | `01 18 18 00` |
| `RMID` | mRoomId | `17 00 10 00` |
| `DESC` | mDescription | `05 20 28 00` |
| `MLST` | mMaps | `02 18 50 00` |
| `MODS` | mMod | `15 18 38 00` |
| `MRID` | mMapRotationId | `11 18 10 00` |
| `NAME` | mName | `05 20 18 00` |
| `TYPE` | mType | `05 00 40 00` |
| `KSUM` | mKeyScopeNameValueMap | `01 18 30 00` |
| `LBID` | mBoardId | `14 18 20 00` |
| `NAME` | mBoardName | `05 20 10 00` |
| `POFF` | mPeriodOffset | `14 18 28 00` |
| `PRID` | mPeriodId | `14 00 24 00` |
| `CAT ` | mCategory | `05 20 10 00` |
| `EID ` | mEntityId | `1b 18 20 00` |
| `KSUM` | mKeyScopeNameValueMap | `01 18 80 00` |
| `PTYP` | mPeriodTypes | `02 18 d0 00` |
| `UPDT` | mUpdates | `02 00 28 00` |
| `053 ` | mLanguage | `01 00 00 00` |
| `KSSV` | mKeyScopeStatsValueMap | `01 00 10 00` |
| `BIDL` | mRemovedUserList | `02 18 20 00` |
| `CTID` | mCategoryId | `17 18 18 00` |
| `RMID` | mRoomId | `17 00 10 00` |
| `END ` | mEnd | `15 18 14 00` |
| `STRT` | mStart | `15 00 10 00` |
| `ACFG` | mAdminConfig | `0a 18 10 00` |
| `MLST` | mMapRotations | `02 18 00 02` |
| `PCAT` | mPresetSettingsCategories | `02 18 a0 00` |
| `PLST` | mPresets | `02 18 a8 01` |
| `PSET` | mPresetSettings | `02 18 f8 00` |
| `PSLS` | mPingSites | `02 18 48 00` |
| `PVAL` | mPresetSettingsRanges | `02 00 50 01` |
| `CAT ` | mCategory | `05 20 10 00` |
| `EID ` | mEntityIds | `02 18 30 00` |
| `ETYP` | mEntityType | `0b 10 20 00` |
| `KSLS` | mKeyScopeNameValueMap | `01 18 b0 00` |
| `NAME` | mStatNames | `02 18 70 00` |
| `POFF` | mPeriodOffset | `14 18 2c 00` |
| `PRID` | mPeriodId | `14 18 28 00` |
| `PTYP` | mPeriodType | `14 00 24 00` |
| `STRL` | mStringstoVerify | `02 00 10 00` |

## (unnamed table @ 0x0001416c7510)

`0x0001416c7510` - 15 fields

| tag | field | meta |
| --- | --- | --- |
| `ADRS` | mAddress | `05 20 10 00` |
| `ANON` | mIsAnonymous | `0f 18 84 00` |
| `DISA` | mDisable | `05 20 38 00` |
| `EDCT` | mEnableDisconnectTelemetry | `0f 18 b0 00` |
| `FILT` | mFilter | `05 20 68 00` |
| `LOC ` | mLocale | `15 18 80 00` |
| `MINR` | mUnderage | `0f 18 98 00` |
| `NOOK` | mNoToggleOk | `05 20 48 00` |
| `PORT` | mPort | `15 18 20 00` |
| `SDLY` | mSendDelay | `15 18 7c 00` |
| `SESS` | mSessionID | `05 20 88 00` |
| `SKEY` | mKey | `05 20 28 00` |
| `SPCT` | mSendPercentage | `15 18 78 00` |
| `STIM` | mUseServerTime | `05 20 58 00` |
| `SVNM` | mTelemetryServiceName | `05 00 a0 00` |

## (unnamed table @ 0x0001416c77b8)

`0x0001416c77b8` - 20 fields

| tag | field | meta |
| --- | --- | --- |
| `KSVL` | mKeyScopeValues | `01 00 10 00` |
| `ATTR` | mMemberAttributes | `01 18 20 00` |
| `EID ` | mBlazeId | `18 18 18 00` |
| `RMID` | mRoomId | `17 00 10 00` |
| `GPVS` | mGameProtocolVersionString | `05 20 18 00` |
| `PID ` | mPurchaseId | `16 00 10 00` |
| `EID ` | mEntityId | `1b 18 18 00` |
| `ETP ` | mEntityType | `0b 10 10 00` |
| `KSNM` | mKeyScopeName | `05 20 20 00` |
| `KSNV` | mNewKeyScopeValue | `16 18 38 00` |
| `KSOV` | mOldKeyScopeValue | `16 00 30 00` |
| `SID ` | mServerId | `15 00 10 00` |
| `CAT ` | mCategory | `05 20 10 00` |
| `KSUM` | mKeyScopeNameValueMap | `01 18 30 00` |
| `POFF` | mPeriodOffset | `14 18 28 00` |
| `PRID` | mPeriodId | `14 18 24 00` |
| `PTYP` | mPeriodType | `14 00 20 00` |
| `PLST` | mPingSites | `02 00 10 00` |
| `ATKN` | mAuthToken | `05 20 10 00` |
| `BODY` | mPayload | `0a 00 20 00` |

## (unnamed table @ 0x0001416c7a20)

`0x0001416c7a20` - 17 fields

| tag | field | meta |
| --- | --- | --- |
| `MAC ` | mMacAddress | `05 00 10 00` |
| `VWID` | mViewId | `17 00 10 00` |
| `ATTR` | mRoomAttributes | `01 18 60 01` |
| `CAPA` | mCapacity | `15 18 68 00` |
| `CMET` | mClientMetaData | `01 18 c0 00` |
| `CNAM` | mCatName | `05 20 28 00` |
| `CRIT` | mEntryCriteria | `01 18 70 00` |
| `DESC` | mDescription | `05 20 58 00` |
| `DNAM` | mDisplayName | `05 20 38 00` |
| `GMET` | mGameMetaData | `01 18 10 01` |
| `JOIN` | mJoinIfExists | `0f 18 b0 01` |
| `PASS` | mPassword | `05 20 48 00` |
| `VNAM` | mViewName | `05 20 18 00` |
| `VWID` | mViewId | `17 00 10 00` |
| `KEY ` | mKey | `05 20 10 00` |
| `VAL ` | mValue | `12 00 20 00` |
| `GDAT` | mGameData | `02 00 10 00` |

## (unnamed table @ 0x0001416d78c0)

`0x0001416d78c0` - 8 fields

| tag | field | meta |
| --- | --- | --- |
| `AID ` | mAccountId | `16 18 48 00` |
| `ALOC` | mAccountLocale | `15 18 50 00` |
| `EXBB` | mExternalBlob | `08 10 30 00` |
| `EXID` | mExternalId | `17 18 28 00` |
| `ID  ` | mBlazeId | `18 18 20 00` |
| `NAME` | mName | `05 20 10 00` |
| `ORIG` | mOriginPersonaId | `17 18 58 00` |
| `PIDI` | mPidId | `16 00 60 00` |

## (unnamed table @ 0x0001416d7980)

`0x0001416d7980` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `CRIT` | mRoleEntryCriteriaMap | `01 18 10 00` |
| `RCAP` | mRoleCapacity | `13 00 60 00` |
| `ULST` | mUserIdentificationList | `02 00 10 00` |

## (unnamed table @ 0x0001416d79c8)

`0x0001416d79c8` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `MOD ` | mCustomModRuleCriteria | `0a 00 10 00` |

## (unnamed table @ 0x0001416d79e0)

`0x0001416d79e0` - 8 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 18 10 00` |
| `NTID` | mNewTeamId | `13 18 1a 00` |
| `OTID` | mOldTeamId | `13 18 18 00` |
| `TIDX` | mTeamIndex | `13 00 1c 00` |
| `CNTX` | mPlayerRemovedTitleContext | `13 18 58 00` |
| `GID ` | mGameId | `17 18 10 00` |
| `PLST` | mPlayerIds | `02 00 18 00` |
| `LMAP` | mMachineLoadCapacityMap | `01 00 10 00` |

## (unnamed table @ 0x0001416d7aa8)

`0x0001416d7aa8` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `RVAL` | mMatchedRankFlags | `11 00 10 00` |

## (unnamed table @ 0x0001416d7ac0)

`0x0001416d7ac0` - 10 fields

| tag | field | meta |
| --- | --- | --- |
| `ADDR` | mAddress | `09 10 98 01` |
| `BPS ` | mBestPingSiteAlias | `05 20 a0 00` |
| `CTY ` | mCountry | `05 20 c8 01` |
| `CVAR` | mClientData | `06 10 a0 01` |
| `DMAP` | mDataMap | `01 18 10 00` |
| `HWFG` | mHardwareFlags | `07 10 b8 01` |
| `PSLM` | mLatencyList | `02 18 b0 00` |
| `QDAT` | mQosData | `0a 18 f0 00` |
| `UATT` | mUserInfoAttribute | `17 18 d8 01` |
| `ULST` | mBlazeObjectIdList | `02 00 60 00` |

## (unnamed table @ 0x0001416d7ba8)

`0x0001416d7ba8` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `THLD` | mMinFitThresholdName | `05 00 10 00` |
| `ULST` | mUserIdList | `02 00 10 00` |
| `RNME` | mRuleName | `05 20 10 00` |
| `THLS` | mThresholdNames | `02 18 20 00` |
| `WGHT` | mWeight | `15 00 60 00` |

## (unnamed table @ 0x0001416d7c50)

`0x0001416d7c50` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `SKEY` | mSessionKey | `05 00 10 00` |

## (unnamed table @ 0x0001416d7c70)

`0x0001416d7c70` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `ATTR` | mPlayerAttribs | `01 18 70 00` |
| `GID ` | mGameId | `17 18 10 00` |
| `PID ` | mPlayerId | `18 00 18 00` |
| `CTID` | mComponentId | `13 00 10 00` |
| `UID ` | mBlazeId | `18 00 10 00` |

## (unnamed table @ 0x0001416d7cf0)

`0x0001416d7cf0` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGameData | `0a 18 f0 04` |
| `LFPJ` | mIsLockableForPreferredJoins | `0f 18 d0 05` |
| `PROS` | mGameRoster | `02 18 f8 04` |
| `QUEU` | mGameQueue | `02 18 50 05` |
| `REAS` | mGameSetupReason | `09 00 a8 05` |

## (unnamed table @ 0x0001416d7db0)

`0x0001416d7db0` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `AGN ` | mNumOfActiveGame | `15 18 14 00` |
| `GACD` | mGameAttributesData | `02 18 20 00` |
| `JPN ` | mNumOfJoinedPlayer | `15 18 18 00` |
| `LSN ` | mNumOfLoggedSession | `15 18 10 00` |
| `MMSN` | mNumOfMatchmakingSession | `15 00 1c 00` |

## (unnamed table @ 0x0001416d7e28)

`0x0001416d7e28` - 14 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 00 10 00` |
| `MLST` | mRegisteredMachineList | `02 00 10 00` |
| `GID ` | mGameId | `17 18 10 00` |
| `PID ` | mBlazeId | `18 00 18 00` |
| `GID ` | mGameId | `17 18 10 00` |
| `PCAP` | mSlotCapacities | `02 18 18 00` |
| `RNFO` | mRoleInformation | `0a 18 b0 00` |
| `TLST` | mTeamDetailsList | `02 00 58 00` |
| `ID  ` | mUserId | `18 00 10 00` |
| `ULST` | mUserIdList | `02 00 10 00` |
| `CRIT` | mEntryCriteriaMap | `01 18 18 00` |
| `GMID` | mGameId | `17 18 10 00` |
| `IGNO` | mIgnoreEntryCriteriaWithInvite | `0f 18 d0 00` |
| `RCRT` | mRoleEntryCriteriaMap | `01 00 68 00` |

## (unnamed table @ 0x0001416d7f80)

`0x0001416d7f80` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GMID` | mGameId | `17 18 10 00` |
| `GMRG` | mGameModRegister | `15 00 18 00` |

## (unnamed table @ 0x0001416d7fb0)

`0x0001416d7fb0` - 9 fields

| tag | field | meta |
| --- | --- | --- |
| `FIT ` | mFitScore | `15 18 00 04` |
| `GAM ` | mGameData | `0a 00 f8 03` |
| `PDRC` | mPredefinedRuleConfig | `0a 18 10 00` |
| `POSV` | mPossibleValues | `02 00 78 00` |
| `GID ` | mGameId | `17 18 10 00` |
| `OVRD` | mOverridePlayerRole | `0f 18 22 00` |
| `PID ` | mPlayerId | `18 18 18 00` |
| `ROLE` | mPlayerRole | `05 20 28 00` |
| `TIDX` | mPlayerTeamIndex | `13 00 20 00` |

## (unnamed table @ 0x0001416d8098)

`0x0001416d8098` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `FLGS` | mStatusFlags | `07 10 18 00` |
| `ID  ` | mBlazeId | `18 00 10 00` |

## (unnamed table @ 0x0001416d80c0)

`0x0001416d80c0` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `PCAP` | mMaxPlayerCapacity | `13 18 6a 00` |
| `PCNT` | mDesiredPlayerCount | `13 18 68 00` |
| `PMIN` | mMinPlayerCount | `13 18 6c 00` |
| `SDIF` | mMaxTeamSizeDifferenceAllowed | `13 18 6e 00` |
| `THLD` | mRangeOffsetListName | `05 20 10 00` |
| `TID ` | mTeamId | `13 18 20 00` |
| `TLST` | mTeamIdVector | `02 00 28 00` |

## (unnamed table @ 0x0001416d8170)

`0x0001416d8170` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 18 10 00` |
| `GNAM` | mGameName | `05 00 18 00` |
| `MLST` | mMachineIdList | `02 00 10 00` |

## (unnamed table @ 0x0001416d81c0)

`0x0001416d81c0` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `DATA` | mExtendedData | `0a 18 f0 01` |
| `SUBS` | mSubscribed | `0f 18 00 02` |
| `USID` | mUserId | `18 00 f8 01` |
| `GID ` | mGameId | `17 00 10 00` |

## (unnamed table @ 0x0001416d8220)

`0x0001416d8220` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 18 10 00` |
| `PDAT` | mJoiningPlayer | `0a 00 c0 01` |
| `ID  ` | mBlazeId | `18 00 10 00` |

## (unnamed table @ 0x0001416d8270)

`0x0001416d8270` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `NOMM` | mNumOfMatchmakingSessions | `15 00 10 00` |
| `LAHE` | mLastAuthError | `05 20 20 00` |
| `LLUD` | mLastLocaleUsed | `05 00 10 00` |
| `GID ` | mGameId | `17 18 10 00` |
| `HOST` | mNewHostPlayer | `18 00 18 00` |

## (unnamed table @ 0x0001416d8370)

`0x0001416d8370` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `CRIT` | mEntryCriteriaMap | `01 18 18 00` |
| `GMID` | mGameId | `17 18 10 00` |
| `IGNO` | mIgnoreEntryCriteriaWithInvite | `0f 18 d0 00` |
| `RCRT` | mRoleEntryCriteriaMap | `01 00 68 00` |
| `DNAM` | mListConfigName | `05 20 90 00` |
| `GLST` | mGameIds | `02 18 10 00` |
| `PIDL` | mPersistedGameIdList | `02 00 50 00` |

## (unnamed table @ 0x0001416d8420)

`0x0001416d8420` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 18 10 00` |
| `NPSI` | mNpSessionId | `05 20 48 00` |
| `XNNC` | mXnetNonce | `08 10 18 00` |
| `XSES` | mXnetSession | `08 00 30 00` |
| `CAP ` | mMaxResultCount | `15 18 20 00` |
| `PREF` | mPrefixName | `05 00 10 00` |

## (unnamed table @ 0x0001416d84b0)

`0x0001416d84b0` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `RMAP` | mRoleSizeMap | `01 18 18 00` |
| `TID ` | mTeamId | `13 18 10 00` |
| `TSZE` | mTeamSize | `13 00 12 00` |
| `MLST` | mMachineIdList | `02 00 10 00` |
| `BANM` | mBannedMembers | `02 00 10 00` |

## (unnamed table @ 0x0001416d86a8)

`0x0001416d86a8` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `ERR ` | mJoinErr | `15 00 10 00` |

## (unnamed table @ 0x0001416d86c0)

`0x0001416d86c0` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 18 10 00` |
| `PIDL` | mPlayerIdList | `02 00 18 00` |

## (unnamed table @ 0x0001416d8770)

`0x0001416d8770` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `TMAX` | mMaxTeamSizeAccepted | `13 18 10 00` |
| `TMIN` | mMinTeamSizeAccepted | `13 00 12 00` |

## (unnamed table @ 0x0001416d87a0)

`0x0001416d87a0` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 18 10 00` |
| `PID ` | mPlayerId | `18 00 18 00` |

## (unnamed table @ 0x0001416d87d0)

`0x0001416d87d0` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `DATA` | mExtendedData | `0a 18 58 02` |
| `USER` | mUserInfo | `0a 00 10 00` |

## (unnamed table @ 0x0001416d8800)

`0x0001416d8800` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 18 10 00` |
| `GSET` | mGameSettings | `07 00 18 00` |
| `UID ` | mUserId | `18 00 10 00` |
| `GID ` | mGameId | `17 18 10 00` |
| `GNAM` | mGameName | `05 00 18 00` |
| `GID ` | mGameId | `17 18 10 00` |
| `LGAM` | mSwapPlayers | `02 00 18 00` |

## (unnamed table @ 0x0001416d88b8)

`0x0001416d88b8` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GREQ` | mCreateGameRequest | `0a 18 20 00` |
| `MID ` | mMachineId | `05 00 10 00` |

## (unnamed table @ 0x0001416d88f0)

`0x0001416d88f0` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `CDAT` | mCustomData | `08 10 20 00` |
| `GID ` | mGameId | `17 18 10 00` |
| `PID ` | mPlayerId | `18 00 18 00` |
| `DNAM` | mListConfigName | `05 20 88 00` |
| `GRP ` | mUserSetId | `0c 10 78 00` |
| `USER` | mUser | `0a 00 10 00` |

## (unnamed table @ 0x0001416d8978)

`0x0001416d8978` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 18 10 00` |
| `PID ` | mAdminPlayerId | `18 00 18 00` |

## (unnamed table @ 0x0001416d89a8)

`0x0001416d89a8` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `BUID` | mUserId | `18 00 10 00` |

## (unnamed table @ 0x0001416d89c0)

`0x0001416d89c0` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `ATTR` | mGameAttributes | `01 18 18 00` |
| `GID ` | mGameId | `17 00 10 00` |

## (unnamed table @ 0x0001416d89f0)

`0x0001416d89f0` - 15 fields

| tag | field | meta |
| --- | --- | --- |
| `ISSG` | mIsSingleGroupMatch | `11 18 10 00` |
| `PCAP` | mMaxPlayerCapacity | `13 18 2a 00` |
| `PCNT` | mDesiredPlayerCount | `13 18 28 00` |
| `PMIN` | mMinPlayerCount | `13 18 2c 00` |
| `THLD` | mMinFitThresholdName | `05 00 18 00` |
| `DNAM` | mListConfigName | `05 20 28 06` |
| `GLID` | mListCriteria | `0a 18 10 00` |
| `GVER` | mGameProtocolVersionString | `05 20 10 06` |
| `IGNO` | mIgnoreGameEntryCriteria | `0f 18 38 06` |
| `LCAP` | mListCapacity | `15 18 20 06` |
| `NOJM` | mIgnoreGameJoinMethod | `0f 18 39 06` |
| `RMAP` | mRoleMap | `01 18 40 06` |
| `TID ` | mTeamId | `13 00 3a 06` |
| `UFAT` | mUserFirstAuthTime | `16 18 10 00` |
| `ULAT` | mUserLastAuthTime | `16 00 18 00` |

## (unnamed table @ 0x0001416d8b70)

`0x0001416d8b70` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `ATTN` | mAttributeName | `05 20 10 00` |
| `ATTV` | mAttributevalue | `05 20 20 00` |
| `NOFG` | mNumOfGames | `15 18 30 00` |
| `NOFP` | mNumOfPlayers | `15 00 34 00` |

## (unnamed table @ 0x0001416d8be8)

`0x0001416d8be8` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 00 10 00` |
| `LGAM` | mGames | `02 00 10 00` |

## (unnamed table @ 0x0001416d8c18)

`0x0001416d8c18` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GRID` | mUserGroupId | `0c 10 10 00` |
| `RPVC` | mRequiresClientVersionCheck | `0f 00 20 00` |

## (unnamed table @ 0x0001416d8c40)

`0x0001416d8c40` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `ASIL` | mMatchmakingAsyncStatusList | `02 18 20 00` |
| `MSID` | mMatchmakingSessionId | `17 18 18 00` |
| `USID` | mUserSessionId | `17 00 10 00` |
| `GID ` | mGameId | `17 18 10 00` |
| `LGAM` | mSwapPlayersTeam | `02 00 18 00` |

## (unnamed table @ 0x0001416d8cb8)

`0x0001416d8cb8` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 18 10 00` |
| `REX ` | mJoinedReservedExternalPlayers | `02 00 18 00` |
| `BUID` | mUserId | `18 00 10 00` |

## (unnamed table @ 0x0001416d8d08)

`0x0001416d8d08` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `RSTR` | mTeamRoster | `02 18 18 00` |
| `TID ` | mTeamId | `13 00 10 00` |

## (unnamed table @ 0x0001416d8d40)

`0x0001416d8d40` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `ATTR` | mPlayerAttributes | `01 18 20 00` |
| `GID ` | mGameId | `17 18 10 00` |
| `PID ` | mPlayerId | `18 00 18 00` |

## (unnamed table @ 0x0001416d8d88)

`0x0001416d8d88` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `PMAX` | mMaxPlayerCountAccepted | `15 18 14 00` |
| `PMIN` | mMinPlayerCountAccepted | `15 00 10 00` |
| `BUID` | mUserId | `18 00 10 00` |

## (unnamed table @ 0x0001416d8dd0)

`0x0001416d8dd0` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 18 10 00` |
| `PHID` | mPlatformHostId | `18 18 20 00` |
| `PHST` | mPlatformHostSlotId | `11 00 18 00` |

## (unnamed table @ 0x0001416d8e18)

`0x0001416d8e18` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 00 10 00` |
| `CAP ` | mMaxPlayerCapacity | `15 18 10 00` |
| `PSAS` | mPingSiteAlias | `05 20 18 00` |
| `VSTR` | mGameProtocolVersionString | `05 00 28 00` |
| `USID` | mUserSetId | `0c 00 10 00` |

## (unnamed table @ 0x0001416d8e98)

`0x0001416d8e98` - 8 fields

| tag | field | meta |
| --- | --- | --- |
| `DATA` | mGameData | `0a 00 f0 04` |
| `GID ` | mGameId | `17 18 10 00` |
| `NTID` | mNewTeamId | `13 18 18 00` |
| `TIDX` | mTeamIndex | `13 00 1a 00` |
| `SID ` | mUsersessionidList | `02 00 10 00` |
| `CDAT` | mCustomData | `08 10 20 00` |
| `GID ` | mGameId | `17 18 10 00` |
| `PID ` | mPlayerId | `18 00 18 00` |

## (unnamed table @ 0x0001416d9070)

`0x0001416d9070` - 28 fields

| tag | field | meta |
| --- | --- | --- |
| `AGAM` | mAvoidGamesRuleCriteria | `0a 18 00 03` |
| `APLR` | mAvoidPlayersRuleCriteria | `0a 18 50 03` |
| `CUST` | mCustomRulePrefs | `0a 18 c8 04` |
| `CVAR` | mVariableCustomRulePrefs | `01 18 00 05` |
| `DNF ` | mDNFRulePrefs | `0a 18 18 02` |
| `FRES` | mFreePlayerSlotsRuleCriteria | `0a 18 c0 05` |
| `GEO ` | mGeoLocationRuleCriteria | `0a 18 c0 02` |
| `GNAM` | mGameNameRuleCriteria | `0a 18 e0 02` |
| `MODR` | mModRuleCriteria | `0a 18 b0 04` |
| `NAT ` | mHostBalancingRulePrefs | `0a 18 80 01` |
| `PCNT` | mPlayerCountRuleCriteria | `0a 18 68 05` |
| `PCTF` | mPlayerSlotUtilizationRuleCriteria | `0a 18 d8 05` |
| `PPLR` | mPreferredPlayersRuleCriteria | `0a 18 e0 03` |
| `PSR ` | mPingSiteRulePrefs | `0a 18 30 02` |
| `RANK` | mRankedGameRulePrefs | `0a 18 10 00` |
| `REP ` | mReputationRulePrefs | `0a 18 60 00` |
| `RLST` | mGenericRulePrefsList | `02 18 50 02` |
| `RSZR` | mRosterSizeRulePrefs | `0a 18 a8 02` |
| `SIZE` | mGameSizeRulePrefs | `0a 18 78 00` |
| `SKLZ` | mSkillRulePrefsList | `02 18 c0 01` |
| `TBR ` | mTeamBalanceRulePrefs | `0a 18 18 01` |
| `TCNR` | mTeamCountRulePrefs | `0a 18 68 01` |
| `TEAM` | mTeamSizeRulePrefs | `0a 18 a8 00` |
| `TMSR` | mTeamMinSizeRulePrefs | `0a 18 40 01` |
| `TOTS` | mTotalPlayerSlotsRuleCriteria | `0a 18 98 05` |
| `UED ` | mUEDRuleCriteriaMap | `01 18 48 04` |
| `VIAB` | mHostViabilityRulePrefs | `0a 18 a0 01` |
| `VIRT` | mVirtualGameRulePrefs | `0a 00 38 00` |

## (unnamed table @ 0x0001416d9310)

`0x0001416d9310` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `PCAP` | mMaxPlayerCount | `13 18 12 00` |
| `PMIN` | mMinPlayerCount | `13 00 10 00` |
| `GLID` | mListId | `17 18 10 00` |
| `MAXF` | mMaxPossibleFitScore | `15 18 18 00` |
| `NGD ` | mNumberOfGamesToBeDownloaded | `15 00 1c 00` |
| `BUID` | mOnline | `0f 00 10 00` |

## (unnamed table @ 0x0001416d93a0)

`0x0001416d93a0` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 18 10 00` |
| `GRID` | mGameReportingId | `17 00 18 00` |
| `GMID` | mGameId | `17 18 10 00` |
| `GMRG` | mGameModRegister | `15 00 18 00` |

## (unnamed table @ 0x0001416d94b0)

`0x0001416d94b0` - 21 fields

| tag | field | meta |
| --- | --- | --- |
| `CGS ` | mCreateGameStatus | `0a 18 28 02` |
| `CUST` | mCustomAsynStatus | `0a 18 d0 02` |
| `CVAR` | mVariableCustomAsyncStatus | `01 18 e0 02` |
| `DNFS` | mDNFRuleStatus | `0a 18 38 01` |
| `FGS ` | mFindGameStatus | `0a 18 10 02` |
| `GEOS` | mGeoLocationRuleStatus | `0a 18 50 02` |
| `GRDA` | mGenericRuleStatusMap | `01 18 a8 01` |
| `GSRD` | mGameSizeRuleStatus | `0a 18 10 00` |
| `HBRD` | mHostBalanceRuleStatus | `0a 18 08 01` |
| `HVRD` | mHostViabilityRuleStatus | `0a 18 20 01` |
| `PLCN` | mPlayerCountRuleStatus | `0a 18 48 03` |
| `PLUT` | mPlayerSlotUtilizationRuleStatus | `0a 18 78 03` |
| `PSRS` | mPingSiteRuleStatus | `0a 18 58 01` |
| `RRDA` | mRankRuleStatus | `0a 18 d8 00` |
| `SKRS` | mSkillRuleStatusMap | `01 18 70 00` |
| `TBRS` | mTeamBalanceRuleStatus | `0a 18 40 00` |
| `TMSS` | mTeamMinSizeRuleStatus | `0a 18 58 00` |
| `TOTS` | mTotalPlayerSlotsRuleStatus | `0a 18 60 03` |
| `TSRS` | mTeamSizeRuleStatus | `0a 18 28 00` |
| `UEDS` | mUEDRuleStatusMap | `01 18 68 02` |
| `VGRS` | mVirtualGameRuleStatus | `0a 00 f0 00` |

## (unnamed table @ 0x0001416d96a8)

`0x0001416d96a8` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `ULST` | mUserDataList | `02 00 10 00` |
| `ETOK` | mCachedExternalSessionToken | `05 20 20 00` |
| `EXID` | mExternalId | `17 18 10 00` |
| `IRES` | mReserved | `0f 00 18 00` |

## (unnamed table @ 0x0001416d9710)

`0x0001416d9710` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 00 10 00` |
| `NQOS` | mNetworkQosData | `0a 00 10 00` |
| `GLID` | mListId | `17 00 10 00` |
| `CVAR` | mClientData | `06 00 10 00` |

## (unnamed table @ 0x0001416d9860)

`0x0001416d9860` - 9 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 00 10 00` |
| `CNTY` | mCountry | `05 20 30 00` |
| `CTY ` | mCity | `05 20 20 00` |
| `ID  ` | mBlazeId | `18 18 10 00` |
| `LAT ` | mLatitude | `14 18 18 00` |
| `LON ` | mLongitude | `14 18 1c 00` |
| `OPT ` | mOptIn | `0f 18 50 00` |
| `OVER` | mIsOverridden | `0f 18 51 00` |
| `ST  ` | mStateRegion | `05 00 40 00` |

## (unnamed table @ 0x0001416d9968)

`0x0001416d9968` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 00 10 00` |

## (unnamed table @ 0x0001416d99e0)

`0x0001416d99e0` - 11 fields

| tag | field | meta |
| --- | --- | --- |
| `CRIT` | mRoleCriteriaMap | `01 18 10 00` |
| `RCRT` | mMultiRoleCriteria | `01 00 78 00` |
| `GID ` | mGameId | `17 00 10 00` |
| `ETOK` | mCachedExternalSessionToken | `05 20 18 00` |
| `EXID` | mExternalId | `17 00 10 00` |
| `ATTV` | mAttributeBits | `17 18 50 00` |
| `MASK` | mMaskBits | `17 18 58 00` |
| `ULST` | mBlazeObjectIdList | `02 00 10 00` |
| `GLST` | mGenericRules | `02 18 20 01` |
| `PPSR` | mPingSiteRule | `0a 18 68 00` |
| `RLST` | mPredefinedRules | `02 00 10 00` |

## (unnamed table @ 0x0001416d9b48)

`0x0001416d9b48` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `THLD` | mMinFitThresholdName | `05 00 10 00` |
| `GIDL` | mGameIdList | `02 18 10 00` |
| `PIDL` | mPersistedGameIdList | `02 00 50 00` |
| `GID ` | mGameId | `17 00 10 00` |

## (unnamed table @ 0x0001416d9c30)

`0x0001416d9c30` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 00 10 00` |

## (unnamed table @ 0x0001416d9c48)

`0x0001416d9c48` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `GNUM` | mNumOfGames | `15 00 10 00` |

## (unnamed table @ 0x0001416d9c60)

`0x0001416d9c60` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `COMP` | mComponent | `13 18 14 00` |
| `KEY ` | mKey | `13 18 12 00` |
| `OPER` | mRemove | `0f 18 10 00` |
| `VALU` | mValue | `16 00 18 00` |

## (unnamed table @ 0x0001416d9cc8)

`0x0001416d9cc8` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `PID ` | mPlayerId | `18 18 10 00` |
| `ROLE` | mPlayerRole | `05 00 18 00` |

## (unnamed table @ 0x0001416d9d00)

`0x0001416d9d00` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `NAME` | mRuleName | `05 20 10 00` |
| `SKMN` | mMinSkillAccepted | `16 18 20 00` |
| `SKMX` | mMaxSkillAccepted | `16 00 28 00` |
| `ID  ` | mBlazeId | `18 18 10 00` |
| `OPT ` | mOptIn | `0f 00 18 00` |
| `COID` | mCorrelationId | `05 00 10 00` |
| `PELM` | mPermissionsByComponent | `01 00 10 00` |

## (unnamed table @ 0x0001416d9eb8)

`0x0001416d9eb8` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `VALU` | mMatchedValues | `02 00 10 00` |

## (unnamed table @ 0x0001416d9ed8)

`0x0001416d9ed8` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `DNF ` | mMaxDNFValue | `16 00 10 00` |

## (unnamed table @ 0x0001416d9ef0)

`0x0001416d9ef0` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `COID` | mExternalSessionCorrelationId | `05 20 48 00` |
| `ESNM` | mExternalSessionName | `05 20 38 00` |
| `MSID` | mSessionId | `17 18 10 00` |
| `SCID` | mScid | `05 20 18 00` |
| `STMN` | mExternalSessionTemplateName | `05 00 28 00` |

## (unnamed table @ 0x0001416d9ff0)

`0x0001416d9ff0` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `DONE` | mIsFinalUpdate | `11 18 18 00` |
| `GLID` | mListId | `17 18 10 00` |
| `REMV` | mRemovedGameList | `02 18 20 00` |
| `UPDT` | mUpdatedGames | `02 00 60 00` |

## (unnamed table @ 0x0001416da050)

`0x0001416da050` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `ATTR` | mGameAttribs | `01 18 18 00` |
| `GID ` | mGameId | `17 00 10 00` |

## (unnamed table @ 0x0001416da080)

`0x0001416da080` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `HWFG` | mHardwareFlags | `07 00 10 00` |

## (unnamed table @ 0x0001416da0c0)

`0x0001416da0c0` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `GID ` | mGameId | `17 18 10 00` |
| `NPSI` | mNpSessionId | `05 20 48 00` |
| `XNNC` | mXnetNonce | `08 10 18 00` |
| `XSES` | mXnetSession | `08 00 30 00` |

## (unnamed table @ 0x0001416da168)

`0x0001416da168` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `ATTR` | mGameSettings | `07 10 18 00` |
| `GID ` | mGameId | `17 00 10 00` |
| `ATID` | mKey | `17 18 18 00` |
| `OPER` | mRemove | `0f 18 10 00` |
| `UREA` | mUpdateReason | `15 18 28 00` |
| `VALU` | mValue | `17 00 20 00` |

## (unnamed table @ 0x0001416da1f0)

`0x0001416da1f0` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `EVST` | mEvaluateStatus | `07 10 18 00` |
| `MMSN` | mNumOfMatchmakingSession | `15 18 10 00` |
| `NOMP` | mNumOfMatchedPlayers | `15 00 14 00` |

## (unnamed table @ 0x0001416da230)

`0x0001416da230` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `NAME` | mRuleName | `05 20 10 00` |
| `THLD` | mMinFitThresholdName | `05 20 20 00` |
| `VALU` | mDesiredValues | `02 00 30 00` |
| `MAXF` | mMaxPossibleFitScore | `15 18 10 00` |
| `NGD ` | mNumberOfGamesToBeDownloaded | `15 18 14 00` |
| `UPDT` | mGameList | `02 00 18 00` |

## (unnamed table @ 0x0001416da2d8)

`0x0001416da2d8` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `MSG ` | mErrMessage | `05 00 10 00` |

## (unnamed table @ 0x0001416da2f8)

`0x0001416da2f8` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `MDNF` | mMyDNFValue | `16 18 18 00` |
| `XDNF` | mMaxDNFValue | `16 00 10 00` |

## (unnamed table @ 0x0001416da330)

`0x0001416da330` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `EDAT` | mExtendedData | `0a 18 78 00` |
| `FLGS` | mStatusFlags | `07 10 58 02` |
| `USER` | mUserInfo | `0a 00 10 00` |

## (unnamed table @ 0x0001416da370)

`0x0001416da370` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `MSID` | mMatchmakingSessionId | `17 00 10 00` |

## (unnamed table @ 0x0001416da388)

`0x0001416da388` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `NAME` | mRuleName | `05 20 10 00` |
| `VALU` | mMatchedValues | `02 00 20 00` |

## (unnamed table @ 0x0001416da480)

`0x0001416da480` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `CAP ` | mSlotCapacities | `02 18 18 00` |
| `GID ` | mGameId | `17 18 10 00` |
| `LFPJ` | mLockedForPreferredJoins | `0f 18 78 01` |
| `RNFO` | mRoleInformation | `0a 18 b0 00` |
| `TRST` | mTeamRosters | `02 00 58 00` |

## (unnamed table @ 0x0001416da4f8)

`0x0001416da4f8` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `THLD` | mMinFitThresholdName | `05 00 10 00` |
| `GAME` | mGame | `0a 18 f0 04` |
| `PROS` | mGameRoster | `02 00 f8 04` |

## (unnamed table @ 0x0001416da550)

`0x0001416da550` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `CONG` | mConnectionGroupId | `17 18 20 00` |
| `CSID` | mConnectionSlotId | `11 18 28 00` |
| `HPID` | mPlayerId | `18 18 10 00` |
| `HSLT` | mSlotId | `11 00 18 00` |

## (unnamed table @ 0x0001416da5f0)

`0x0001416da5f0` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `MODS` | mMods | `15 18 10 00` |
| `THLD` | mMinFitThresholdName | `05 00 18 00` |

## (unnamed table @ 0x0001416da658)

`0x0001416da658` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `CPCM` | mConnectedPlayerCounts | `01 00 10 00` |
| `GID ` | mGameId | `17 18 10 00` |
| `PID ` | mPlayerId | `18 00 18 00` |

## (unnamed table @ 0x0001416ecc78)

`0x0001416ecc78` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `MAP ` | mMapId | `14 18 10 00` |
| `MODE` | mMode | `05 00 18 00` |

## (unnamed table @ 0x0001416eccb0)

`0x0001416eccb0` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `LOSS` | mLosses | `13 18 12 00` |
| `POIN` | mPoints | `13 18 16 00` |
| `TIES` | mTies | `13 18 14 00` |
| `WINS` | mWins | `13 00 10 00` |

## (unnamed table @ 0x0001416ecd10)

`0x0001416ecd10` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `DUR ` | mDurationSec | `03 18 14 00` |
| `TIME` | mReplayTimes | `15 00 10 00` |

## (unnamed table @ 0x0001416ecd40)

`0x0001416ecd40` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `CLUB` | mClubReports | `01 18 78 00` |
| `PLYR` | mPlayerReports | `01 00 10 00` |

## (unnamed table @ 0x0001416ecd70)

`0x0001416ecd70` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `ISSG` | mIsSingleGroupMatch | `11 18 10 00` |
| `PCAP` | mMaxPlayerCount | `13 18 2a 00` |
| `PCNT` | mDesiredPlayerCount | `13 18 28 00` |
| `PMIN` | mMinPlayerCount | `13 18 2c 00` |
| `THLD` | mRangeOffsetListName | `05 00 18 00` |

## (unnamed table @ 0x0001416ecdf0)

`0x0001416ecdf0` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `DUR ` | mDurationSec | `03 18 14 00` |
| `GNAM` | mGameName | `05 20 28 00` |
| `GPRP` | mProgressPercentage | `03 18 38 00` |
| `MAP ` | mMapName | `05 20 18 00` |
| `RATG` | mRating | `14 18 3c 00` |
| `TIME` | mReplayTimes | `15 00 10 00` |

## (unnamed table @ 0x0001416ece98)

`0x0001416ece98` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `FCAP` | mFlagsCaptured | `15 00 10 00` |

## (unnamed table @ 0x0001416eceb0)

`0x0001416eceb0` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `DETH` | mDeaths | `13 18 12 00` |
| `FCAP` | mFlagsCaptured | `15 18 14 00` |
| `KILL` | mKills | `13 00 10 00` |

## (unnamed table @ 0x0001416ecef8)

`0x0001416ecef8` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGameAttrs | `0a 18 78 00` |
| `PLYR` | mPlayerReports | `01 00 10 00` |

## (unnamed table @ 0x0001416ecf28)

`0x0001416ecf28` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `PMAX` | mMaxPlayerCountAccepted | `13 18 12 00` |
| `PMIN` | mMinPlayerCountAccepted | `13 00 10 00` |

## (unnamed table @ 0x0001416ecf58)

`0x0001416ecf58` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `THLD` | mMinFitThresholdName | `05 00 10 00` |

## (unnamed table @ 0x0001416ecf78)

`0x0001416ecf78` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGameAttrs | `0a 18 78 00` |
| `PLYR` | mPlayerReports | `01 00 10 00` |

## (unnamed table @ 0x0001416ecfa8)

`0x0001416ecfa8` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `DIST` | mMaxDistance | `15 00 10 00` |

## (unnamed table @ 0x0001416ecfc0)

`0x0001416ecfc0` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `DESS` | mDesiredTotalPlayerSlots | `13 18 22 00` |
| `MAXS` | mMaxTotalPlayerSlots | `13 18 24 00` |
| `MINS` | mMinTotalPlayerSlots | `13 18 20 00` |
| `THLD` | mRangeOffsetListName | `05 00 10 00` |

## (unnamed table @ 0x0001416ed028)

`0x0001416ed028` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGameAttrs | `0a 18 78 00` |
| `PLYR` | mPlayerReports | `01 00 10 00` |

## (unnamed table @ 0x0001416ed060)

`0x0001416ed060` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `DUR ` | mDurationSec | `03 18 14 00` |
| `GNAM` | mGameName | `05 20 28 00` |
| `MAP ` | mMapName | `05 20 18 00` |
| `TIME` | mReplayTimes | `15 00 10 00` |

## (unnamed table @ 0x0001416ed0d0)

`0x0001416ed0d0` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGameAttrs | `0a 18 78 00` |
| `PLYR` | mPlayerReports | `01 00 10 00` |

## (unnamed table @ 0x0001416ed100)

`0x0001416ed100` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `FCAP` | mFlagsCaptured | `15 18 10 00` |
| `LOC ` | mAccountLocale | `15 18 18 00` |
| `RMR ` | mLeavingReason | `15 00 14 00` |

## (unnamed table @ 0x0001416ed178)

`0x0001416ed178` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `PMAX` | mMaxTotalPlayerSlotsAccepted | `13 18 12 00` |
| `PMIN` | mMinTotalPlayerSlotsAccepted | `13 00 10 00` |

## (unnamed table @ 0x0001416ed1d8)

`0x0001416ed1d8` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `SUBS` | mSearchString | `05 00 10 00` |

## (unnamed table @ 0x0001416ed200)

`0x0001416ed200` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `DERV` | mCustomReport | `06 10 18 00` |
| `DETH` | mDeaths | `13 18 12 00` |
| `KILL` | mKills | `13 18 10 00` |
| `WEPN` | mWeapon | `14 00 14 00` |

## (unnamed table @ 0x0001416ed258)

`0x0001416ed258` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `VVAL` | mMatchedVirtualizedFlags | `11 00 10 00` |

## (unnamed table @ 0x0001416ed270)

`0x0001416ed270` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `DETH` | mDeaths | `13 18 12 00` |
| `FCAP` | mFlagsCaptured | `15 18 14 00` |
| `KILL` | mKills | `13 18 10 00` |
| `LOC ` | mAccountLocale | `15 18 84 00` |
| `RMR ` | mLeavingReason | `15 18 80 00` |
| `RSMP` | mResultMap | `01 18 30 00` |
| `SKRP` | mSkippedReport | `06 00 18 00` |

## (unnamed table @ 0x0001416ed310)

`0x0001416ed310` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `MAXS` | mMaxFreePlayerSlots | `13 18 12 00` |
| `MINS` | mMinFreePlayerSlots | `13 00 10 00` |

## (unnamed table @ 0x0001416ed340)

`0x0001416ed340` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `DERV` | mCustomReport | `06 10 18 00` |
| `DETH` | mDeaths | `13 18 12 00` |
| `KILL` | mKills | `13 18 10 00` |
| `LOC ` | mAccountLocale | `15 18 34 00` |
| `RMR ` | mLeavingReason | `15 00 30 00` |

## (unnamed table @ 0x0001416ed3b0)

`0x0001416ed3b0` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `CLUB` | mClubReports | `01 18 10 00` |
| `OFFS` | mOffensiveAthleteReports | `01 18 e0 00` |
| `PLYR` | mPlayerReports | `01 00 78 00` |

## (unnamed table @ 0x0001416ed3f8)

`0x0001416ed3f8` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `LTAL` | mLongestTimeAlive | `13 00 10 00` |

## (unnamed table @ 0x0001416ed410)

`0x0001416ed410` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `DETH` | mDeaths | `13 18 12 00` |
| `FCAP` | mFlagsCaptured | `15 18 14 00` |
| `KILL` | mKills | `13 18 10 00` |
| `RSMP` | mResultMap | `01 18 20 00` |
| `WEPN` | mWeapon | `14 00 18 00` |

## (unnamed table @ 0x0001416ed488)

`0x0001416ed488` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `LOSS` | mLosses | `13 18 12 00` |
| `WINS` | mWins | `13 00 10 00` |

## (unnamed table @ 0x0001416ed4c0)

`0x0001416ed4c0` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `DESP` | mDesiredPercentFull | `11 18 21 00` |
| `MAXP` | mMaxPercentFull | `11 18 22 00` |
| `MINP` | mMinPercentFull | `11 18 20 00` |
| `THLD` | mRangeOffsetListName | `05 00 10 00` |

## (unnamed table @ 0x0001416ed528)

`0x0001416ed528` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `GIDL` | mGameIdList | `02 00 10 00` |

## (unnamed table @ 0x0001416ed540)

`0x0001416ed540` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `DUR ` | mDurationSec | `03 18 14 00` |
| `GNAM` | mGameName | `05 20 28 00` |
| `LEVL` | mLevel | `14 18 38 00` |
| `MAP ` | mMapName | `05 20 18 00` |
| `TIME` | mReplayTimes | `15 00 10 00` |

## (unnamed table @ 0x0001416ed5d0)

`0x0001416ed5d0` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `DUR ` | mDurationSec | `03 18 14 00` |
| `GNAM` | mGameName | `05 20 28 00` |
| `GSNA` | mGameSettingsName | `05 20 38 00` |
| `GSVA` | mOpenToBrowsing | `05 20 48 00` |
| `MAP ` | mMapName | `05 20 18 00` |
| `TIME` | mReplayTimes | `15 00 10 00` |

## (unnamed table @ 0x0001416ed680)

`0x0001416ed680` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `SCOR` | mPlayerScores | `01 18 50 00` |
| `WINP` | mWinners | `02 00 10 00` |

## (unnamed table @ 0x0001416ed6b0)

`0x0001416ed6b0` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `PMAX` | mMaxPercentFullAccepted | `11 18 11 00` |
| `PMIN` | mMinPercentFullAccepted | `11 00 10 00` |

## (unnamed table @ 0x0001416ed6e0)

`0x0001416ed6e0` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `HITS` | mHits | `13 18 18 00` |
| `PID ` | mPlayerId | `18 18 10 00` |
| `SERV` | mServes | `13 18 1a 00` |
| `TEAM` | mTeam | `13 00 1c 00` |

## (unnamed table @ 0x0001416ed740)

`0x0001416ed740` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `DUR ` | mDurationSec | `03 18 14 00` |
| `GNAM` | mGameName | `05 20 28 00` |
| `LEVL` | mLevel | `14 18 38 00` |
| `MAP ` | mMapName | `05 20 18 00` |
| `TIME` | mReplayTimes | `15 00 10 00` |

## (unnamed table @ 0x0001416ed7c8)

`0x0001416ed7c8` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `SDIF` | mMaxTeamSizeDifferenceAllowed | `13 18 20 00` |
| `THLD` | mRangeOffsetListName | `05 00 10 00` |

## (unnamed table @ 0x0001416ed800)

`0x0001416ed800` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `DUR ` | mDurationSec | `03 18 14 00` |
| `GNAM` | mGameName | `05 20 28 00` |
| `GSNA` | mGameSettingsName | `05 20 38 00` |
| `GSVA` | mOpenToBrowsing | `05 20 48 00` |
| `MAP ` | mMapName | `05 20 18 00` |
| `TIME` | mReplayTimes | `15 00 10 00` |

## (unnamed table @ 0x0001416ed8b0)

`0x0001416ed8b0` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `CLID` | mClubId | `17 18 10 00` |
| `PNTS` | mPoints | `13 18 18 00` |
| `RPTS` | mRivalPoints | `13 00 1a 00` |

## (unnamed table @ 0x0001416ed8f8)

`0x0001416ed8f8` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGameAttrs | `0a 18 78 00` |
| `PLYR` | mPlayerReports | `01 00 10 00` |

## (unnamed table @ 0x0001416ed928)

`0x0001416ed928` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `ALST` | mAvoidList | `02 18 50 00` |
| `ASTS` | mAvoidListIds | `02 00 10 00` |

## (unnamed table @ 0x0001416ed958)

`0x0001416ed958` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGameAttrs | `0a 18 78 00` |
| `PLYR` | mPlayerReports | `01 00 10 00` |

## (unnamed table @ 0x0001416ed988)

`0x0001416ed988` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGameAttrs | `0a 18 78 00` |
| `PLYR` | mPlayerReports | `01 00 10 00` |

## (unnamed table @ 0x0001416ed9b8)

`0x0001416ed9b8` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `SDIF` | mMaxTeamSizeDifferenceAccepted | `13 00 10 00` |

## (unnamed table @ 0x0001416ed9d0)

`0x0001416ed9d0` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `CLID` | mClubId | `17 18 10 00` |
| `CREG` | mClubregion | `15 18 1c 00` |
| `PNTS` | mPoints | `13 00 18 00` |

## (unnamed table @ 0x0001416eda20)

`0x0001416eda20` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `PLST` | mPreferredList | `02 18 28 00` |
| `PSET` | mPreferredListId | `0c 10 18 00` |
| `REQP` | mRequirePreferredPlayer | `0f 00 10 00` |

## (unnamed table @ 0x0001416eda60)

`0x0001416eda60` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `CUST` | mCustomReports | `06 10 a0 00` |
| `GAME` | mGameAttrs | `0a 18 78 00` |
| `PLYR` | mPlayerReports | `01 00 10 00` |

## (unnamed table @ 0x0001416edaa0)

`0x0001416edaa0` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGameAttrs | `0a 18 78 00` |
| `PLYR` | mPlayerReports | `01 00 10 00` |

## (unnamed table @ 0x0001416edad0)

`0x0001416edad0` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `FCAP` | mFlagsCaptured | `15 00 10 00` |

## (unnamed table @ 0x0001416edae8)

`0x0001416edae8` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `PCNT` | mTeamMinSize | `13 18 20 00` |
| `THLD` | mRangeOffsetListName | `05 00 10 00` |

## (unnamed table @ 0x0001416edb20)

`0x0001416edb20` - 10 fields

| tag | field | meta |
| --- | --- | --- |
| `CREG` | mClubRegion | `15 18 10 00` |
| `LOSS` | mLosses | `13 18 1a 00` |
| `PNTS` | mPoints | `13 18 1e 00` |
| `RLOS` | mRivalLosses | `13 18 22 00` |
| `RPTS` | mRivalPoints | `13 18 26 00` |
| `RTIE` | mRivalTies | `13 18 24 00` |
| `RWIN` | mRivalWins | `13 18 20 00` |
| `SLVL` | mSeasonLevel | `15 18 14 00` |
| `TIES` | mTies | `13 18 1c 00` |
| `WINS` | mWins | `13 00 18 00` |

## (unnamed table @ 0x0001416edc10)

`0x0001416edc10` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `ATHL` | mOffensiveAthletes | `01 18 e0 00` |
| `CLUB` | mClubReports | `01 18 78 00` |
| `PLYR` | mPlayerReports | `01 00 10 00` |

## (unnamed table @ 0x0001416edc60)

`0x0001416edc60` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `CVAL` | mClientUEDSearchValue | `16 18 30 00` |
| `NAME` | mRuleName | `05 20 10 00` |
| `OVAL` | mOverrideUEDValue | `16 18 38 00` |
| `THLD` | mThresholdName | `05 00 20 00` |

## (unnamed table @ 0x0001416edcd0)

`0x0001416edcd0` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `HITS` | mHits | `13 18 12 00` |
| `SERV` | mServes | `13 00 10 00` |

## (unnamed table @ 0x0001416edd00)

`0x0001416edd00` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `PCNT` | mTeamMinSizeAccepted | `13 00 10 00` |

## (unnamed table @ 0x0001416edd18)

`0x0001416edd18` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `TCNT` | mTeamCount | `13 00 10 00` |

## (unnamed table @ 0x0001416edd30)

`0x0001416edd30` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `ACCR` | mAccuracy | `03 18 14 00` |
| `DERV` | mCustomReport | `06 10 20 00` |
| `DETH` | mDeaths | `13 18 12 00` |
| `KILL` | mKills | `13 18 10 00` |
| `SCOR` | mScore | `15 00 18 00` |

## (unnamed table @ 0x0001416edda0)

`0x0001416edda0` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `FCAP` | mFlagsCaptured | `15 18 14 00` |
| `KILL` | mKills | `13 00 10 00` |

## (unnamed table @ 0x0001416eddd0)

`0x0001416eddd0` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `AMAX` | mMaxUEDAccepted | `16 18 30 00` |
| `AMIN` | mMinUEDAccepted | `16 18 28 00` |
| `MUED` | mMyUEDValue | `16 18 20 00` |
| `NAME` | mRuleName | `05 00 10 00` |

## (unnamed table @ 0x0001416ede38)

`0x0001416ede38` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGameAttrs | `0a 18 78 00` |
| `PLYR` | mPlayerReports | `01 00 10 00` |

## (unnamed table @ 0x0001416ede68)

`0x0001416ede68` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `CLUB` | mClubId | `17 18 18 00` |
| `PTS ` | mPoints | `13 00 10 00` |

## (unnamed table @ 0x0001416edea0)

`0x0001416edea0` - 12 fields

| tag | field | meta |
| --- | --- | --- |
| `DETH` | mDeaths | `13 18 12 00` |
| `GLRD` | mGlickoRd | `14 18 28 00` |
| `GSPT` | mGlickoSkillPoints | `14 18 24 00` |
| `KILL` | mKills | `13 18 10 00` |
| `LOSR` | mLoser | `0f 18 1d 00` |
| `LSPT` | mLobbySkillPoints | `14 18 20 00` |
| `MONY` | mMoney | `15 18 18 00` |
| `PCLS` | mPlayerClass | `14 18 30 00` |
| `RANK` | mRank | `14 18 2c 00` |
| `TALV` | mLongestTimeAlive | `15 18 14 00` |
| `WDNF` | mWinnerByDNF | `0f 18 1e 00` |
| `WINR` | mWinner | `0f 00 1c 00` |

## (unnamed table @ 0x0001416edfc0)

`0x0001416edfc0` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `DETH` | mDeaths | `13 18 10 00` |
| `RSMP` | mResultMap | `01 00 18 00` |

## (unnamed table @ 0x0001416edff0)

`0x0001416edff0` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `ACCR` | mAccuracy | `03 18 18 00` |
| `DETH` | mDeaths | `13 18 12 00` |
| `FCAP` | mFlagsCaptured | `15 18 14 00` |
| `KILL` | mKills | `13 18 10 00` |
| `SCOR` | mScore | `15 00 1c 00` |

## (unnamed table @ 0x0001416ee070)

`0x0001416ee070` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GNAM` | mGameName | `05 20 20 00` |
| `MAP ` | mMapName | `05 00 10 00` |

## (unnamed table @ 0x0001416ee0b0)

`0x0001416ee0b0` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `ISEN` | mIsEnabled | `0f 18 14 00` |
| `MODS` | mDesiredModRegister | `15 00 10 00` |

## (unnamed table @ 0x0001416ee0e0)

`0x0001416ee0e0` - 28 fields

| tag | field | meta |
| --- | --- | --- |
| `DUR ` | mDurationSec | `03 18 14 00` |
| `GNAM` | mGameName | `05 20 28 00` |
| `GPRP` | mProgressPercentage | `03 18 38 00` |
| `MAP ` | mMapName | `05 20 18 00` |
| `RATG` | mRating | `14 18 3c 00` |
| `TIME` | mReplayTimes | `15 00 10 00` |
| `ERR ` | mError | `0a 00 10 00` |
| `LKRS` | mContentInfoList | `02 00 10 00` |
| `ENAB` | mEnableKillswitch | `0e 00 10 00` |
| `CCAT` | mContentCategory | `05 20 18 00` |
| `CID ` | mContentId | `16 18 10 00` |
| `RATE` | mRating | `15 00 28 00` |
| `AMSA` | mAssociatedMaxSizeAllowed | `15 18 64 00` |
| `COTY` | mContextType | `05 20 50 00` |
| `DAFO` | mDataFormat | `05 20 28 00` |
| `ENTY` | mEntityType | `05 20 38 00` |
| `ID  ` | mId | `13 18 20 00` |
| `MASA` | mMaxSizeAllowed | `15 18 60 00` |
| `MAXA` | mMaxAllowed | `15 18 48 00` |
| `MBMA` | mMaxBookmarksAllowed | `13 18 4c 00` |
| `NAME` | mName | `05 20 10 00` |
| `RATE` | mRatings | `0f 18 24 00` |
| `SECU` | mSecurePut | `0e 18 68 00` |
| `TAGS` | mTags | `0f 18 22 00` |
| `USAG` | mUsage | `0f 00 23 00` |
| `PGID` | mId | `17 18 10 00` |
| `PRES` | mSessionChanging | `0e 00 18 00` |
| `UID ` | mUserId | `18 00 10 00` |

## (unnamed table @ 0x0001416f5510)

`0x0001416f5510` - 64 fields

| tag | field | meta |
| --- | --- | --- |
| `INFO` | mPlaygroupInfo | `0a 18 50 00` |
| `MLST` | mPlaygroupMemberInfoList | `02 18 20 02` |
| `USER` | mJoiningBlazeIds | `02 00 10 00` |
| `CCAT` | mContentCategory | `05 20 18 00` |
| `CID ` | mContentId | `16 18 10 00` |
| `SUBL` | mSubContentNames | `02 00 28 00` |
| `AUTH` | mAuthCredentials | `0a 18 28 00` |
| `PEID` | mPersonaId | `16 18 10 00` |
| `SBID` | mSandboxId | `05 00 18 00` |
| `PLST` | mPurchaseList | `02 00 10 00` |
| `PID ` | mPurchaseId | `16 00 10 00` |
| `CREA` | mDateCreated | `05 20 88 00` |
| `DNAM` | mDisplayName | `05 20 20 00` |
| `IVIS` | mIsVisible | `0e 18 50 00` |
| `LAST` | mLastAuthenticated | `05 20 98 00` |
| `NAME` | mName | `05 20 30 00` |
| `NMSP` | mNamespaceName | `05 20 40 00` |
| `PID ` | mPersonaId | `16 18 10 00` |
| `PPID` | mPidId | `16 18 18 00` |
| `SHOW` | mShowPersona | `05 20 78 00` |
| `SRSN` | mStatusReasonCode | `05 20 68 00` |
| `STAT` | mStatus | `05 00 58 00` |
| `PLST` | mPlaygroupIdList | `02 00 10 00` |
| `DISP` | mDisplay | `14 18 60 00` |
| `FRMT` | mFormat | `05 20 50 00` |
| `LDSC` | mLongDesc | `05 20 30 00` |
| `NAME` | mName | `05 20 10 00` |
| `SDSC` | mShortDesc | `05 20 20 00` |
| `TYPE` | mType | `05 00 40 00` |
| `ATTR` | mAttrs | `02 18 38 00` |
| `CID ` | mContentId | `16 18 18 00` |
| `EID ` | mEntityId | `1b 18 20 00` |
| `ENAM` | mEntityName | `05 20 28 00` |
| `RANK` | mRank | `14 18 10 00` |
| `TAGS` | mTags | `02 00 90 00` |
| `CCAT` | mContentCategory | `05 20 18 00` |
| `CID ` | mContentId | `16 00 10 00` |
| `ANON` | mAnonymousPid | `0e 18 40 01` |
| `ASRC` | mAuthenticationSource | `05 20 10 01` |
| `AUTH` | mLastAuthDate | `05 20 f0 00` |
| `BILL` | mDefaultBillingAddressUri | `05 20 48 01` |
| `CTRY` | mCountry | `05 20 58 00` |
| `DCRE` | mDateCreated | `05 20 d0 00` |
| `DMAL` | mDiscoverableEmail | `05 20 30 01` |
| `DMOD` | mDateModified | `05 20 e0 00` |
| `DOB ` | mDob | `05 20 48 00` |
| `ESTS` | mEmailStatus | `05 20 28 00` |
| `GOPT` | mGlobalOptin | `0e 18 c9 00` |
| `LANG` | mLanguage | `05 20 68 00` |
| `LCLE` | mLocale | `05 20 78 00` |
| `MAIL` | mEmail | `05 20 18 00` |
| `PID ` | mPidId | `17 18 10 00` |
| `PMAL` | mParentalEmail | `05 20 b8 00` |
| `PSTR` | mStrength | `05 20 38 00` |
| `REAS` | mReasonCode | `05 20 98 00` |
| `RSRC` | mRegistrationSource | `05 20 00 01` |
| `SHIP` | mDefaultShippingAddressUri | `05 20 58 01` |
| `SMAL` | mShowEmail | `05 20 20 01` |
| `STAT` | mStatus | `05 20 88 00` |
| `TOPT` | mThirdPartyOptin | `0e 18 c8 00` |
| `TVER` | mTosVersion | `05 20 a8 00` |
| `UAGE` | mUnderagePid | `0e 00 41 01` |
| `PINF` | mPersona | `02 18 10 00` |
| `PURI` | mPersonaUri | `02 00 68 00` |

## (unnamed table @ 0x0001416f5c48)

`0x0001416f5c48` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `PGN ` | mNumOfPlaygroup | `15 18 10 00` |
| `PIPN` | mNumOfPlayersInPlaygroup | `15 00 14 00` |
| `PGID` | mId | `17 00 10 00` |
| `BLID` | mBlazeId | `18 00 10 00` |
| `MSET` | mMailSettings | `0a 00 10 00` |

## (unnamed table @ 0x0001416f5cc0)

`0x0001416f5cc0` - 41 fields

| tag | field | meta |
| --- | --- | --- |
| `MEMB` | mPlaygroupMemberInfoList | `02 18 18 00` |
| `PGID` | mPlaygroupId | `17 00 10 00` |
| `ADDR` | mIpAddress | `05 20 20 00` |
| `TOKN` | mAccessToken | `05 20 10 00` |
| `UAGE` | mIncludeUnderage | `05 00 30 00` |
| `PIDL` | mPackKeyErrorList | `02 00 10 00` |
| `PID ` | mPurchaseId | `16 00 10 00` |
| `INFO` | mContentInfo | `0a 00 10 00` |
| `PEID` | mPersonaId | `16 18 10 00` |
| `PROF` | mProofKey | `05 20 18 00` |
| `TOKN` | mAuthToken | `05 00 28 00` |
| `PINF` | mPersonas | `0a 00 10 00` |
| `INFO` | mContentInfo | `0a 18 18 00` |
| `RANK` | mRank | `14 00 10 00` |
| `GPID` | mGroupId | `0c 10 18 00` |
| `PGID` | mPlaygroupId | `17 00 10 00` |
| `NAME` | mName | `05 20 10 00` |
| `OP  ` | mOperator | `05 20 30 00` |
| `VALU` | mValue | `05 00 20 00` |
| `PID ` | mPurchaseId | `16 00 10 00` |
| `PUR ` | mPurchase | `0a 00 10 00` |
| `CONS` | mIsConsumable | `0e 18 e8 00` |
| `CYCL` | mManagedLifecycle | `0e 18 78 00` |
| `DURI` | mDeviceUri | `05 20 18 00` |
| `EID ` | mEntitlementId | `17 18 10 00` |
| `ESRC` | mEntitlementSource | `05 20 28 00` |
| `ETAG` | mEntitlementTag | `05 20 38 00` |
| `ETYP` | mEntitlementType | `05 20 48 00` |
| `GNAM` | mGroupName | `05 20 68 00` |
| `GRNT` | mGrantDate | `05 20 58 00` |
| `PCAT` | mProductCatalog | `05 20 80 00` |
| `PDID` | mProductId | `05 20 90 00` |
| `PERM` | mOriginPermissions | `15 18 00 01` |
| `PJID` | mProjectId | `05 20 a0 00` |
| `PURI` | mPidUri | `05 20 f0 00` |
| `REAS` | mStatusReasonCode | `05 20 b0 00` |
| `STAT` | mStatus | `05 20 c0 00` |
| `TERM` | mTerminationDate | `05 20 d0 00` |
| `UCNT` | mUseCount | `17 18 e0 00` |
| `VERS` | mVersion | `15 00 04 01` |
| `DESL` | mTemplateList | `02 00 10 00` |

## Blaze::Redirector::XboxServerAddress

`0x0001416f61f0` - 42 fields

| tag | field | meta |
| --- | --- | --- |
| `DPRT` | mDstPort | `13 18 1e 00` |
| `MASK` | mNetMask | `15 18 14 00` |
| `SID ` | mServiceId | `15 18 18 00` |
| `SIP ` | mSrcIp | `15 18 10 00` |
| `SPRT` | mSrcPort | `13 00 1c 00` |
| `PID ` | mPurchaseId | `16 00 10 00` |
| `CAUS` | mCause | `05 20 10 00` |
| `FILD` | mField | `05 20 20 00` |
| `VALU` | mValue | `05 00 30 00` |
| `AUTH` | mAuthCredentials | `0a 18 10 00` |
| `PID ` | mPersonaId | `17 18 58 00` |
| `PPID` | mPid | `17 00 50 00` |
| `TOKN` | mXblToken | `0a 00 10 00` |
| `DNAM` | mDisplayName | `05 20 10 00` |
| `EXTT` | mExternalRefType | `05 20 60 00` |
| `EXTV` | mExternalRefValue | `05 20 70 00` |
| `NSPC` | mNamespaceName | `05 20 20 00` |
| `SHOW` | mShowPersona | `05 20 50 00` |
| `STAT` | mStatus | `05 20 30 00` |
| `STRC` | mStatusReasonCode | `05 00 40 00` |
| `MSET` | mMailSettings | `0a 00 10 00` |
| `STIL` | mTitles | `01 00 10 00` |
| `PLST` | mPackList | `02 00 10 00` |
| `BLID` | mBlazeId | `18 18 10 00` |
| `SKIP` | mSkipMigration | `0e 00 18 00` |
| `GPID` | mGroupId | `0c 10 18 01` |
| `PGID` | mId | `17 18 10 00` |
| `PNET` | mNetworkAddress | `09 10 90 00` |
| `UKEY` | mUniqueKey | `05 20 18 00` |
| `USER` | mUser | `0a 00 28 00` |
| `PID ` | mPackKey | `05 00 10 00` |
| `LIST` | mServers | `02 00 10 00` |
| `PLIC` | mItemKeyList | `02 00 10 00` |
| `BODY` | mPid | `0a 00 10 00` |
| `INFO` | mContentInfo | `0a 00 10 00` |
| `DELE` | mCacheDeletes | `02 00 10 00` |
| `QUAN` | mQuantity | `15 00 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 18 00` |
| `PID ` | mPid | `17 00 10 00` |
| `PERS` | mPersona | `0a 00 10 00` |
| `ERR ` | mErrorStatus | `15 18 20 00` |
| `PKEY` | mPackKey | `05 00 10 00` |

## (unnamed table @ 0x0001416f66b0)

`0x0001416f66b0` - 15 fields

| tag | field | meta |
| --- | --- | --- |
| `DPRT` | mDstPort | `13 18 3a 00` |
| `SID ` | mServiceId | `15 18 20 00` |
| `SIP ` | mHostname | `05 20 10 00` |
| `SITE` | mSiteName | `05 20 28 00` |
| `SPRT` | mSrcPort | `13 00 38 00` |
| `BLID` | mBlazeId | `18 00 10 00` |
| `PID ` | mPackId | `16 18 10 00` |
| `PLIC` | mUserLicenses | `02 00 18 00` |
| `ENTS` | mEntitlement | `02 18 10 00` |
| `EURI` | mEntitlementUri | `02 00 68 00` |
| `INFO` | mPlaygroupInfo | `0a 00 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 10 00` |
| `EXPD` | mExpandResults | `05 20 58 00` |
| `FILT` | mFilter | `0a 18 68 00` |
| `PID ` | mPid | `17 00 50 00` |

## (unnamed table @ 0x0001416f6890)

`0x0001416f6890` - 25 fields

| tag | field | meta |
| --- | --- | --- |
| `ADDR` | mAddress | `09 10 10 00` |
| `AMAP` | mAddressRemaps | `02 18 40 00` |
| `CERT` | mCertificateList | `02 18 38 01` |
| `MSGS` | mMessages | `02 18 f8 00` |
| `NMAP` | mNameRemaps | `02 18 98 00` |
| `SECU` | mSecure | `0f 18 38 00` |
| `XDNS` | mDefaultDnsAddress | `15 00 f0 00` |
| `CCAT` | mCategory | `05 20 10 00` |
| `CID ` | mContentId | `16 18 20 00` |
| `GPID` | mGroupId | `0c 10 28 00` |
| `PSID` | mBlazeId | `18 00 38 00` |
| `HIST` | mIncludeHistory | `0e 18 1a 00` |
| `LCAP` | mListCapacity | `13 18 18 00` |
| `UID ` | mUserId | `18 00 10 00` |
| `BODY` | mEntitlements | `0a 00 10 00` |
| `BITS` | mPublicKeyBits | `14 18 60 00` |
| `ENTR` | mX509EntryMap | `01 18 10 00` |
| `HOST` | mHostname | `05 20 80 00` |
| `NAME` | mServiceName | `05 20 98 00` |
| `PORT` | mPort | `14 18 90 00` |
| `V   ` | mDirtySDKVersion | `05 20 68 00` |
| `VERS` | mDirtyCertVersion | `15 00 78 00` |
| `AUTH` | mAuthCredentials | `0a 18 10 00` |
| `EXPD` | mExpandResults | `05 20 50 00` |
| `FILT` | mFilter | `0a 00 60 00` |

## (unnamed table @ 0x0001416f6b50)

`0x0001416f6b50` - 42 fields

| tag | field | meta |
| --- | --- | --- |
| `AMAP` | mAddressRemaps | `02 18 30 03` |
| `BTGT` | mBuildTarget | `05 20 b0 00` |
| `BTIM` | mBuildTime | `05 20 90 00` |
| `CGVS` | mConfigVersion | `05 20 80 00` |
| `CVER` | mCompatibleClientVersions | `02 18 b0 02` |
| `DEPO` | mDepotLocation | `05 20 c0 00` |
| `INST` | mInstances | `02 18 58 02` |
| `IVER` | mIncompatibleClientVersions | `02 18 f0 02` |
| `LOCN` | mBuildLocation | `05 20 a0 00` |
| `MSTR` | mMasterInstance | `0a 18 d0 00` |
| `NAME` | mName | `05 20 10 00` |
| `NASP` | mPersonaNamespace | `05 20 e8 03` |
| `NMAP` | mNameRemaps | `02 18 88 03` |
| `PLAT` | mPlatform | `05 20 60 00` |
| `SNMS` | mServiceNames | `02 18 20 00` |
| `SVID` | mDefaultServiceId | `15 18 e4 03` |
| `VERS` | mVersion | `05 20 70 00` |
| `XDNS` | mDefaultDnsAddress | `15 18 e0 03` |
| `XMST` | mAuxMasters | `02 18 a8 01` |
| `XSLV` | mAuxSlaves | `02 00 00 02` |
| `PLIC` | mUserLicenses | `02 18 18 00` |
| `UID ` | mUserId | `18 00 10 00` |
| `NAME` | mServiceName | `05 00 10 00` |
| `FLAG` | mFlags | `07 10 10 00` |
| `MGID` | mMessageId | `17 18 20 00` |
| `SMSK` | mStatusMask | `15 18 3c 00` |
| `SRCE` | mSource | `0c 10 28 00` |
| `STAT` | mStatus | `15 18 40 00` |
| `TYPE` | mType | `15 00 38 00` |
| `EGRT` | mEndGrantDate | `05 20 60 00` |
| `ETAG` | mEntitlementTag | `05 20 20 00` |
| `ETRM` | mEndTerminationDate | `05 20 80 00` |
| `ETYP` | mEntitlementType | `05 20 e0 00` |
| `GNAM` | mGroupNames | `02 18 90 00` |
| `HAP ` | mHasAuthorizedPersona | `05 20 f8 00` |
| `PCAT` | mProductCatalog | `05 20 d0 00` |
| `PDID` | mProductId | `05 20 10 00` |
| `PJID` | mProjectId | `15 18 f0 00` |
| `REAS` | mStatusReasonCode | `05 20 40 00` |
| `SGRT` | mStartGrantDate | `05 20 50 00` |
| `STAT` | mStatus | `05 20 30 00` |
| `STRM` | mStartTerminationDate | `05 00 70 00` |

## (unnamed table @ 0x0001416f6fe0)

`0x0001416f6fe0` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `MSGS` | mMessages | `02 00 10 00` |
| `CCAT` | mCategory | `05 20 10 00` |
| `CID ` | mContentId | `16 00 20 00` |

## (unnamed table @ 0x0001416f7030)

`0x0001416f7030` - 32 fields

| tag | field | meta |
| --- | --- | --- |
| `HCID` | mNewHostConnectionGroupId | `17 18 28 00` |
| `HCSD` | mNewHostConnectionSlotId | `11 18 21 00` |
| `HSID` | mNewHostSlotId | `11 18 20 00` |
| `LID ` | mNewLeaderId | `18 18 18 00` |
| `PGID` | mPlaygroupId | `17 00 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 c8 00` |
| `BODY` | mPersonaInfo | `0a 18 20 00` |
| `PEID` | mPersonaId | `17 18 18 00` |
| `PID ` | mPid | `17 00 10 00` |
| `BODY` | mEntitlement | `0a 00 10 00` |
| `PIDL` | mPackKeyList | `02 00 10 00` |
| `CYCL` | mManagedLifecycle | `0e 18 88 00` |
| `DVID` | mDeviceId | `17 18 c8 00` |
| `ESRC` | mEntitlementSource | `05 20 a0 00` |
| `ETAG` | mEntitlementTag | `05 20 30 00` |
| `ETYP` | mEntitlementType | `05 20 b0 00` |
| `GNAM` | mGroupName | `05 20 90 00` |
| `GRNT` | mGrantDate | `05 20 68 00` |
| `PCAT` | mProductCatalog | `05 20 20 00` |
| `PDID` | mProductId | `05 20 10 00` |
| `PERM` | mOriginPermissions | `15 18 d0 00` |
| `PJID` | mProjectId | `15 18 c0 00` |
| `REAS` | mStatusReasonCode | `05 20 50 00` |
| `STAT` | mStatus | `05 20 40 00` |
| `TERM` | mTerminationDate | `05 20 78 00` |
| `UCNT` | mUseCount | `17 18 60 00` |
| `VERS` | mVersion | `15 00 d4 00` |
| `NAME` | mName | `05 20 10 00` |
| `VALU` | mValue | `05 00 20 00` |
| `BLID` | mBlazeId | `18 00 10 00` |
| `UPDT` | mCacheUpdates | `02 00 10 00` |
| `INFO` | mContentInfo | `0a 00 10 00` |

## (unnamed table @ 0x0001416f73a0)

`0x0001416f73a0` - 14 fields

| tag | field | meta |
| --- | --- | --- |
| `ATTR` | mAttrMap | `01 18 d0 00` |
| `FLAG` | mFlags | `07 10 60 00` |
| `STAT` | mStatus | `15 18 78 00` |
| `TAG ` | mTag | `15 18 74 00` |
| `TIDS` | mTargetIds | `02 18 58 00` |
| `TTYP` | mTargetType | `0b 10 10 00` |
| `TYPE` | mType | `15 00 70 00` |
| `CERT` | mCertificateList | `02 00 10 00` |
| `DESC` | mDescriptionText | `05 20 50 00` |
| `LIPA` | mClosedImagePath | `05 20 40 00` |
| `PKEY` | mPackKey | `05 20 10 00` |
| `SIPA` | mOpenImagePath | `05 20 30 00` |
| `VNAM` | mVisualName | `05 00 20 00` |
| `PURI` | mPersonaUri | `05 00 10 00` |

## (unnamed table @ 0x0001416f7510)

`0x0001416f7510` - 24 fields

| tag | field | meta |
| --- | --- | --- |
| `LID ` | mBlazeId | `18 18 18 00` |
| `PERM` | mPermissions | `07 10 20 00` |
| `PGID` | mPlaygroupId | `17 00 10 00` |
| `CNT ` | mCount | `15 18 50 00` |
| `ENV ` | mEnvironment | `05 20 20 00` |
| `NAME` | mName | `05 20 10 00` |
| `PLAT` | mPlatform | `05 20 30 00` |
| `PROF` | mConnectionProfile | `05 00 40 00` |
| `TAG ` | mTag | `05 20 18 00` |
| `TGID` | mTagId | `17 00 10 00` |
| `MSLT` | mMessages | `02 00 10 00` |
| `FLAG` | mFlags | `07 10 10 00` |
| `MGID` | mMessageId | `17 18 20 00` |
| `SMSK` | mStatusMask | `15 18 4c 00` |
| `SRCE` | mSource | `0c 10 28 00` |
| `STAT` | mStatus | `15 18 50 00` |
| `TARG` | mTarget | `0c 10 38 00` |
| `TMSK` | mTouchStatusMask | `15 18 54 00` |
| `TSTA` | mTouchStatus | `15 18 58 00` |
| `TYPE` | mType | `15 00 48 00` |
| `CAT ` | mCategory | `05 20 10 00` |
| `CID ` | mContentId | `16 18 20 00` |
| `CTYP` | mContextType | `0b 10 2c 00` |
| `ETYP` | mEntityType | `0b 00 28 00` |

## (unnamed table @ 0x0001416f77b8)

`0x0001416f77b8` - 35 fields

| tag | field | meta |
| --- | --- | --- |
| `GTAG` | mGamertag | `05 20 18 00` |
| `XUID` | mXuid | `17 00 10 00` |
| `CCAT` | mContentCategory | `05 20 18 00` |
| `CID ` | mContentId | `16 00 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 40 01` |
| `EID ` | mEntitlementId | `17 18 20 00` |
| `EXPD` | mExpandResults | `05 20 30 01` |
| `INFO` | mEntitlementSearchParams | `0a 18 28 00` |
| `PEID` | mPersonaId | `17 18 18 00` |
| `PID ` | mPid | `17 00 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 20 00` |
| `PEID` | mPersonaId | `17 18 18 00` |
| `PID ` | mPid | `17 00 10 00` |
| `ATTR` | mPlaygroupAttributes | `01 18 18 00` |
| `PGID` | mPlaygroupId | `17 00 10 00` |
| `MCNT` | mCount | `15 00 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 f8 00` |
| `BODY` | mEntitlementInfo | `0a 18 20 00` |
| `EID ` | mEntitlementId | `16 18 18 00` |
| `PID ` | mPid | `17 00 10 00` |
| `LKRS` | mContentInfo | `02 18 18 00` |
| `MSIZ` | mSizeAllowed | `14 18 10 00` |
| `TCNT` | mTotalCount | `15 00 70 00` |
| `LIST` | mLeaderboardSummaries | `02 00 10 00` |
| `DDAT` | mDownDate | `05 20 30 00` |
| `DMSG` | mDownMessage | `05 20 40 00` |
| `WDAT` | mWarnDate | `05 20 10 00` |
| `WMSG` | mWarnMessage | `05 00 20 00` |
| `ATTR` | mAttrMap | `01 18 30 00` |
| `FLAG` | mFlags | `07 10 10 00` |
| `STAT` | mStatus | `15 18 28 00` |
| `TAG ` | mTag | `15 18 24 00` |
| `TYPE` | mType | `15 00 20 00` |
| `PYLD` | mPayload | `0a 18 e8 00` |
| `SRCE` | mSource | `0c 00 f0 00` |

## (unnamed table @ 0x0001416f7b80)

`0x0001416f7b80` - 13 fields

| tag | field | meta |
| --- | --- | --- |
| `ATTR` | mMemberAttributes | `01 18 88 00` |
| `CONG` | mConnectionGroupId | `17 18 68 01` |
| `CSID` | mConnectionSlotId | `11 18 70 01` |
| `GPID` | mGroupId | `0c 10 78 01` |
| `JTIM` | mJoinTime | `15 18 64 01` |
| `PERM` | mPermissions | `07 10 78 00` |
| `PNET` | mNetworkAddress | `09 10 d8 00` |
| `SID ` | mSlotId | `11 18 60 01` |
| `USER` | mUser | `0a 18 10 00` |
| `UUID` | mUUID | `05 00 88 01` |
| `LKRS` | mContentInfoMap | `01 18 18 00` |
| `MSIZ` | mSizeAllowed | `14 18 10 00` |
| `TCNT` | mTotalCount | `15 00 80 00` |

## (unnamed table @ 0x0001416f7ca8)

`0x0001416f7ca8` - 10 fields

| tag | field | meta |
| --- | --- | --- |
| `ATTR` | mPlaygroupAttributes | `01 18 18 00` |
| `PGID` | mPlaygroupId | `17 00 10 00` |
| `MCNT` | mCount | `15 00 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 28 00` |
| `PID ` | mPid | `17 18 10 00` |
| `TYPE` | mOptinType | `05 00 18 00` |
| `AUTH` | mAuthCredentials | `0a 18 f0 00` |
| `BODY` | mEntitlementInfo | `0a 18 18 00` |
| `PID ` | mPid | `17 00 10 00` |
| `INFO` | mContentInfo | `0a 00 10 00` |

## (unnamed table @ 0x0001416f7e00)

`0x0001416f7e00` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `MGID` | mMessageId | `17 18 10 00` |
| `MIDS` | mMessageIds | `02 00 18 00` |
| `LIST` | mCategorySummaries | `02 00 10 00` |

## (unnamed table @ 0x0001416f7ea0)

`0x0001416f7ea0` - 36 fields

| tag | field | meta |
| --- | --- | --- |
| `EXBL` | mExternalBlob | `08 10 40 00` |
| `EXID` | mExternalId | `17 18 38 00` |
| `FLAG` | mFlags | `07 10 58 00` |
| `MGID` | mMessageId | `17 18 10 00` |
| `NAME` | mSourceName | `05 20 28 00` |
| `PYLD` | mPayload | `0a 18 48 01` |
| `SRCE` | mSource | `0c 10 18 00` |
| `TIME` | mTimestamp | `15 00 68 00` |
| `CAT ` | mCategory | `05 20 10 00` |
| `CID ` | mContentId | `16 18 20 00` |
| `CTYP` | mContextType | `0b 10 2c 00` |
| `ETYP` | mEntityType | `0b 10 28 00` |
| `HIDE` | mHide | `0f 18 e0 00` |
| `TAGS` | mTags | `02 18 88 00` |
| `UPDT` | mAttributes | `02 00 30 00` |
| `CCAT` | mContentCategory | `05 20 50 00` |
| `CIDS` | mContentId | `02 18 10 00` |
| `PSID` | mBlazeId | `18 00 60 00` |
| `ATTR` | mMemberAttributes | `01 18 20 00` |
| `EID ` | mBlazeId | `18 18 18 00` |
| `PGID` | mPlaygroupId | `17 00 10 00` |
| `OTYP` | mOptin | `05 00 10 00` |
| `EURI` | mEntitlementUri | `05 00 10 00` |
| `PGPS` | mPlaygroupInfoList | `02 00 10 00` |
| `GPID` | mGroupId | `0c 10 e8 01` |
| `JOIN` | mJoinIfExists | `0f 18 e0 01` |
| `PGRP` | mPlaygroupInfo | `0a 00 10 00` |
| `MIDS` | mMessageIds | `02 00 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 68 00` |
| `BODY` | mPidProfilePostRequest | `01 18 18 00` |
| `PID ` | mPid | `17 00 10 00` |
| `MNAP` | mVariableValueMap | `01 18 20 00` |
| `MTPL` | mPurpose | `05 00 10 00` |
| `AUTH` | mAuthCredentials | `0a 00 10 00` |
| `END ` | mEnd | `15 18 14 00` |
| `STRT` | mStart | `15 00 10 00` |

## (unnamed table @ 0x0001416f82c0)

`0x0001416f82c0` - 7 fields

| tag | field | meta |
| --- | --- | --- |
| `ATTR` | mMemberAttributes | `01 18 20 00` |
| `EID ` | mBlazeId | `18 18 18 00` |
| `PGID` | mPlaygroupId | `17 00 10 00` |
| `MCNT` | mCount | `15 00 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 20 00` |
| `EID ` | mEntitlementId | `16 18 10 00` |
| `PEID` | mPersonaId | `17 00 18 00` |

## (unnamed table @ 0x0001416f8368)

`0x0001416f8368` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `PGID` | mId | `17 18 10 00` |
| `XNNC` | mXnetNonce | `08 10 18 00` |
| `XSES` | mXnetSession | `08 00 30 00` |

## (unnamed table @ 0x0001416f83e0)

`0x0001416f83e0` - 14 fields

| tag | field | meta |
| --- | --- | --- |
| `PGID` | mId | `17 18 10 00` |
| `PRES` | mUsesPresence | `0e 18 48 00` |
| `XNNC` | mXnetNonce | `08 10 18 00` |
| `XSES` | mXnetSession | `08 00 30 00` |
| `MESG` | mMessage | `0a 18 e0 01` |
| `SSID` | mSourceSessionIds | `02 18 50 00` |
| `TUID` | mTargetUserSessionIds | `02 00 10 00` |
| `LBRW` | mTopNList | `02 18 10 00` |
| `SIZE` | mSize | `14 00 68 00` |
| `OPTF` | mEmailOptInFlags | `07 10 18 00` |
| `UID ` | mUserId | `18 00 10 00` |
| `AUTH` | mAuthCredentials | `0a 18 28 00` |
| `PCAT` | mProfileInfoCategory | `05 20 18 00` |
| `PID ` | mPid | `17 00 10 00` |

## (unnamed table @ 0x0001416f8580)

`0x0001416f8580` - 19 fields

| tag | field | meta |
| --- | --- | --- |
| `HOST` | mHostname | `05 20 10 00` |
| `IP  ` | mIp | `15 18 20 00` |
| `PORT` | mPort | `13 00 24 00` |
| `EAPU` | mEntAuthPersonaUri | `05 00 10 00` |
| `CCAT` | mContentCategory | `05 20 10 00` |
| `CIDS` | mContentIds | `02 18 38 00` |
| `DTRG` | mDateRange | `0a 00 20 00` |
| `SIZE` | mSize | `14 18 20 00` |
| `TAGS` | mTagsIncluded | `14 18 24 00` |
| `VIEW` | mLeaderboardView | `05 00 10 00` |
| `PGKY` | mPlaygroupKey | `05 00 10 00` |
| `PGID` | mId | `17 18 10 00` |
| `PRES` | mUsesPresence | `0e 00 18 00` |
| `PROF` | mUserProfiles | `02 00 10 00` |
| `IID ` | mItemId | `15 18 30 00` |
| `PCD ` | mPurchasingComponentData | `05 20 20 00` |
| `PCID` | mPurchasingComponentId | `13 18 18 00` |
| `UID ` | mUserId | `18 00 10 00` |
| `PGID` | mPlaygroupId | `17 00 10 00` |

## (unnamed table @ 0x0001416f87a0)

`0x0001416f87a0` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `PORT` | mPort | `13 18 28 00` |
| `SID ` | mServiceId | `15 18 10 00` |
| `SITE` | mSiteName | `05 00 18 00` |
| `REPS` | mLicenseReports | `01 00 10 00` |
| `GUID` | mPetitionGuid | `05 00 10 00` |

## (unnamed table @ 0x0001416fcc90)

`0x0001416fcc90` - 17 fields

| tag | field | meta |
| --- | --- | --- |
| `ATRB` | mStats | `01 18 10 00` |
| `PLYR` | mPlayerReports | `01 00 60 00` |
| `BLST` | mUnlockBoolList | `02 18 50 00` |
| `CLST` | mConsumableList | `02 18 d0 00` |
| `ILST` | mUnlockIndexList | `02 18 90 00` |
| `ULST` | mUnlockStringList | `02 00 10 00` |
| `TIME` | mSeconds | `14 00 10 00` |
| `COID` | mContentId | `0c 00 10 00` |
| `CKEY` | mKey | `0a 18 10 00` |
| `DTYP` | mType | `14 18 80 00` |
| `ETYP` | mEntityType | `0b 10 48 00` |
| `FRMT` | mFormat | `05 20 70 00` |
| `KIND` | mKind | `05 20 88 00` |
| `LDSC` | mDesc | `05 20 60 00` |
| `META` | mMetadata | `05 20 98 00` |
| `SDSC` | mShortDesc | `05 20 50 00` |
| `UNKV` | mUnknownValue | `05 00 a8 00` |

## (unnamed table @ 0x0001416fce50)

`0x0001416fce50` - 29 fields

| tag | field | meta |
| --- | --- | --- |
| `MAP ` | mMapId | `14 18 10 00` |
| `MODE` | mMode | `14 00 14 00` |
| `GMES` | mGameEvents | `02 18 20 00` |
| `PROC` | mGameEventProcessorName | `05 00 10 00` |
| `ANVP` | mAttributeMap | `01 18 10 00` |
| `EURL` | mExternalURL | `05 00 60 00` |
| `ACCL` | mAccoladeReports | `01 18 e0 00` |
| `DBSP` | mDoubleSP | `01 18 b0 01` |
| `LICN` | mLicenseReports | `01 18 48 01` |
| `RSLT` | mResults | `01 18 10 00` |
| `STAT` | mStats | `01 00 78 00` |
| `GTNA` | mGameTypeName | `05 20 10 00` |
| `HIST` | mHistoryTables | `02 00 20 00` |
| `INVT` | mInventoryContents | `0a 00 10 00` |
| `FILT` | mFilterList | `02 18 78 00` |
| `INFO` | mViewInfo | `0a 18 10 00` |
| `LGRC` | mColumns | `02 18 d0 00` |
| `MAXG` | mMaxGames | `15 18 60 00` |
| `RTYP` | mRowTypeName | `05 00 68 00` |
| `FGRE` | mFlagReason | `05 20 28 00` |
| `FLAG` | mFlags | `17 18 20 00` |
| `GHID` | mGameHistoryId | `17 18 38 00` |
| `GRID` | mGameReportingId | `17 18 10 00` |
| `GTYP` | mGameTypeName | `05 20 40 00` |
| `ONLI` | mOnline | `0e 18 18 00` |
| `TIME` | mTimestamp | `16 18 50 00` |
| `TRM ` | mTableRowMap | `01 00 58 00` |
| `EVET` | mEventMap | `01 00 10 00` |
| `CONC` | mConcours | `01 00 10 00` |

## (unnamed table @ 0x0001416fd140)

`0x0001416fd140` - 9 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mReport | `06 10 28 00` |
| `GRID` | mGameReportingId | `17 18 10 00` |
| `GTYP` | mGameTypeName | `05 20 18 00` |
| `PART` | mOfflineParticipantList | `02 00 40 00` |
| `COID` | mContentId | `0c 10 10 00` |
| `SHOW` | mShow | `0f 00 20 00` |
| `PLAT` | mPlates | `01 00 10 00` |
| `REPS` | mAccoladeReports | `01 00 10 00` |
| `INFO` | mViewInfo | `02 00 10 00` |

## (unnamed table @ 0x0001416fd210)

`0x0001416fd210` - 20 fields

| tag | field | meta |
| --- | --- | --- |
| `CLBS` | mGroupReports | `01 18 c8 00` |
| `GAME` | mGameAttributes | `01 18 10 00` |
| `NATN` | mNationReports | `01 18 98 01` |
| `PLYR` | mPlayerReports | `01 18 60 00` |
| `SRVR` | mServerReports | `01 00 30 01` |
| `ILST` | mItemKeyList | `02 18 18 00` |
| `UID ` | mUserId | `18 00 10 00` |
| `EVED` | mEventData | `06 10 20 00` |
| `EVTN` | mEventType | `05 00 10 00` |
| `MAXR` | mMaxRows | `15 18 60 00` |
| `NAME` | mName | `05 20 10 00` |
| `QVAR` | mQueryVarValues | `02 00 20 00` |
| `ILST` | mItemKeyList | `02 00 10 00` |
| `PAD ` | mPad | `0e 00 10 00` |
| `AIDX` | mIndex | `13 18 30 00` |
| `ANAM` | mAttributeName | `05 20 20 00` |
| `ETYP` | mEntityType | `0b 10 34 00` |
| `EXPR` | mExpression | `05 20 38 00` |
| `HVAR` | mHasVariable | `0e 18 32 00` |
| `TABN` | mTable | `05 00 10 00` |

## Blaze::GameReporting::SubmitGameReportRequest

`0x0001416fd440` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `STAT` | mStats | `01 00 10 00` |
| `ENID` | mEntityIds | `02 18 10 00` |
| `LGRC` | mColumns | `02 00 50 00` |

## (unnamed table @ 0x0001416fd490)

`0x0001416fd490` - 75 fields

| tag | field | meta |
| --- | --- | --- |
| `DATA` | mCustomData | `06 10 28 00` |
| `EROR` | mBlazeError | `14 18 10 00` |
| `FNL ` | mFinalResult | `0f 18 14 00` |
| `GHID` | mGameHistoryId | `17 18 20 00` |
| `GRID` | mGameReportingId | `17 00 18 00` |
| `NATN` | mNationReports | `01 18 78 00` |
| `PLYR` | mPlayerReports | `01 00 10 00` |
| `IKEY` | mItemKey | `05 20 18 00` |
| `LACT` | mLastActivationTime | `15 18 28 00` |
| `UID ` | mUserId | `18 00 10 00` |
| `DATA` | mGameEventData | `06 10 18 00` |
| `GMET` | mGameEventType | `15 00 10 00` |
| `GMRS` | mGameReportList | `02 00 10 00` |
| `CKEY` | mKey | `0a 18 10 00` |
| `DTYP` | mType | `14 18 80 00` |
| `ETYP` | mEntityType | `0b 10 48 00` |
| `FRMT` | mFormat | `05 20 70 00` |
| `KIND` | mKind | `05 20 88 00` |
| `LDSC` | mDesc | `05 20 60 00` |
| `META` | mMetadata | `05 20 98 00` |
| `SDSC` | mShortDesc | `05 20 50 00` |
| `UNKV` | mUnknownValue | `05 20 a8 00` |
| `VALU` | mValues | `02 00 b8 00` |
| `ASST` | mAssists | `14 18 24 00` |
| `DDRV` | mDistDriven | `14 18 30 00` |
| `PLYT` | mPlayTime | `14 18 34 00` |
| `SCOR` | mScore | `14 18 14 00` |
| `SUCD` | mSuicides | `14 18 20 00` |
| `TKDS` | mTakedownStreak | `14 18 28 00` |
| `TKDW` | mTakedowns | `14 18 18 00` |
| `WRCK` | mWrecks | `14 18 1c 00` |
| `WRKS` | mWreckStreak | `14 18 2c 00` |
| `XP  ` | mXp | `14 00 10 00` |
| `COLS` | mColumns | `02 18 60 00` |
| `PKEY` | mPrimaryKey | `02 18 20 00` |
| `TABN` | mTable | `05 00 10 00` |
| `METR` | mMetricName | `05 20 10 00` |
| `VALU` | mValue | `16 00 20 00` |
| `SVMP` | mStatValueScope | `01 00 10 00` |
| `AIDX` | mIndex | `13 18 30 00` |
| `ANAM` | mAttributeName | `05 20 20 00` |
| `TABN` | mTable | `05 00 10 00` |
| `CNSU` | mConsumable | `0a 18 18 00` |
| `UID ` | mUserId | `18 00 10 00` |
| `VNAM` | mName | `05 00 10 00` |
| `SP  ` | mSp | `16 00 10 00` |
| `COUN` | mCountry | `13 18 78 00` |
| `RULE` | mRoadRules | `01 00 10 00` |
| `ACTT` | mActivationTime | `15 18 2c 00` |
| `DSEC` | mSecToDrain | `15 18 28 00` |
| `IKEY` | mItemKey | `05 20 18 00` |
| `UID ` | mUserId | `18 00 10 00` |
| `DESC` | mDesc | `05 20 30 00` |
| `GTYP` | mTypeName | `05 20 20 00` |
| `META` | mMetadata | `05 20 40 00` |
| `VNAM` | mName | `05 00 10 00` |
| `RLIS` | mTableRowList | `02 00 10 00` |
| `SCOR` | mBestAccolade | `14 18 10 00` |
| `SETT` | mWriteBest | `0e 00 14 00` |
| `ENID` | mEntityIds | `02 18 10 00` |
| `LGRC` | mColumnValues | `02 00 50 00` |
| `ID  ` | mId | `15 18 10 00` |
| `TAG ` | mTag | `05 00 18 00` |
| `QUER` | mQueries | `02 00 10 00` |
| `LEFT` | mSecLeft | `15 00 10 00` |
| `ACTT` | mActivationTime | `15 18 24 00` |
| `CKEY` | mConsumableKey | `05 20 10 00` |
| `DURA` | mDurationLeft | `15 18 28 00` |
| `QANT` | mQuantity | `15 00 20 00` |
| `PLAT` | mDoubleSP | `01 00 10 00` |
| `ILST` | mItemKeyList | `02 00 10 00` |
| `MGRR` | mMaxGameReport | `15 18 60 00` |
| `QNAM` | mQueryName | `05 20 10 00` |
| `QUER` | mGameReportQuery | `0a 18 68 00` |
| `QVAR` | mQueryVarValues | `02 00 20 00` |

## (unnamed table @ 0x0001416fdc38)

`0x0001416fdc38` - 38 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGameAttrs | `0a 18 78 00` |
| `PLYR` | mPlayerReports | `01 00 10 00` |
| `CIL ` | mColumnInfoList | `02 00 10 00` |
| `CLST` | mConsumableList | `02 18 58 00` |
| `ILST` | mItemKeyList | `02 18 18 00` |
| `UID ` | mUserId | `18 00 10 00` |
| `EVID` | mEventId | `14 18 10 00` |
| `NUMP` | mNumPlayers | `10 18 18 00` |
| `SCOR` | mScore | `14 18 14 00` |
| `VALD` | mValid | `0e 00 19 00` |
| `COLS` | mColumnKeyList | `02 18 90 00` |
| `FILT` | mFilterList | `02 18 38 00` |
| `GTYP` | mTypeName | `05 20 20 00` |
| `MGRR` | mMaxGameReport | `15 18 30 00` |
| `QNAM` | mName | `05 00 10 00` |
| `VALU` | mValues | `02 00 10 00` |
| `ATMP` | mAttempts | `13 18 22 00` |
| `IPRE` | mIsProgressionEvent | `0e 18 25 00` |
| `MODC` | mModsCount | `15 18 2c 00` |
| `MODU` | mModsUsed | `15 18 28 00` |
| `PBST` | mPb | `0e 18 20 00` |
| `PRPO` | mProgressionPosition | `11 18 24 00` |
| `ROAD` | mRoad | `15 18 10 00` |
| `TIME` | mTimeMs | `14 18 18 00` |
| `VEHI` | mVehicle | `15 18 1c 00` |
| `VETY` | mVehicleType | `11 18 14 00` |
| `WIN ` | mWin | `11 00 21 00` |
| `GRTS` | mGameReportTypes | `02 00 10 00` |
| `ANVP` | mAttributeMap | `01 18 90 00` |
| `COID` | mContentId | `0c 10 10 00` |
| `COTY` | mComplaintType | `05 20 30 00` |
| `PTDE` | mPetitionDetail | `05 20 80 00` |
| `SUBJ` | mSubject | `05 20 20 00` |
| `TMZO` | mTimeZone | `05 20 e0 00` |
| `TRGT` | mTargetUsers | `02 00 40 00` |
| `TROW` | mAttributeMap | `01 00 10 00` |
| `QNAM` | mName | `05 00 10 00` |
| `NAME` | mName | `05 00 10 00` |

## (unnamed table @ 0x0001416fe070)

`0x0001416fe070` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `CTRY` | mCountry | `05 20 20 00` |
| `DETH` | mDeaths | `13 18 12 00` |
| `KILL` | mKills | `13 18 10 00` |
| `MONY` | mMoney | `15 18 18 00` |
| `TALV` | mLongestTimeAlive | `15 00 14 00` |

## (unnamed table @ 0x0001416ffae0)

`0x0001416ffae0` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `LEAG` | mLeagueId | `1b 00 10 00` |

## (unnamed table @ 0x0001416ffb00)

`0x0001416ffb00` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `HITS` | mHits | `13 18 18 00` |
| `PID ` | mPlayerId | `18 18 10 00` |
| `SERV` | mServes | `13 00 1a 00` |

## (unnamed table @ 0x0001416ffb48)

`0x0001416ffb48` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `DEFS` | mDefensivePlayerStats | `0a 18 38 00` |
| `OFFS` | mOffensivePlayerStats | `0a 00 10 00` |
| `CHAL` | mChallenges | `01 18 10 00` |
| `LIST` | mChallengeList | `02 00 78 00` |

## (unnamed table @ 0x0001416ffba8)

`0x0001416ffba8` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `STAT` | mStats | `01 00 10 00` |

## (unnamed table @ 0x0001416ffbc0)

`0x0001416ffbc0` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `CID ` | mClubId | `17 18 10 00` |
| `LOSS` | mLosses | `13 18 1a 00` |
| `PNTS` | mPoints | `13 18 1c 00` |
| `WINS` | mWins | `13 00 18 00` |

## (unnamed table @ 0x0001416ffc20)

`0x0001416ffc20` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `LEAG` | mLeagueId | `1b 18 10 00` |
| `MAP ` | mMapId | `13 00 18 00` |

## (unnamed table @ 0x0001416ffc50)

`0x0001416ffc50` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `DEFS` | mDefensiveAthleteReports | `01 18 00 01` |
| `GAME` | mGameAttrs | `0a 18 10 00` |
| `OFFS` | mOffensiveAthleteReports | `01 18 98 00` |
| `PLYR` | mPlayerReports | `01 00 30 00` |
| `CNT ` | mCount | `15 00 10 00` |

## (unnamed table @ 0x0001416ffcd0)

`0x0001416ffcd0` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGameAttrs | `0a 18 10 00` |
| `OFFS` | mOffensiveAthleteReports | `01 18 98 00` |
| `PLYR` | mPlayerReports | `01 00 30 00` |

## (unnamed table @ 0x0001416ffd18)

`0x0001416ffd18` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `WEAP` | mWeapons | `01 00 10 00` |

## (unnamed table @ 0x0001416ffd30)

`0x0001416ffd30` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `HITS` | mHits | `13 18 18 00` |
| `PID ` | mPlayerId | `18 18 10 00` |
| `SERV` | mServes | `13 00 1a 00` |

## (unnamed table @ 0x0001416ffd78)

`0x0001416ffd78` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `LVL ` | mLevel | `13 00 10 00` |

## (unnamed table @ 0x0001416ffd90)

`0x0001416ffd90` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `LOSS` | mLosses | `13 18 12 00` |
| `SLVL` | mSeasonLevel | `13 18 14 00` |
| `WINS` | mWins | `13 00 10 00` |

## (unnamed table @ 0x0001416ffdd8)

`0x0001416ffdd8` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `PLYR` | mPlayerReports | `01 00 10 00` |

## (unnamed table @ 0x0001416ffdf0)

`0x0001416ffdf0` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGameAttrs | `0a 18 10 00` |
| `OFFS` | mAthleteReports | `01 18 98 00` |
| `PLYR` | mPlayerReports | `01 00 30 00` |

## (unnamed table @ 0x0001416ffe38)

`0x0001416ffe38` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `SERV` | mServes | `13 18 10 00` |
| `TEAM` | mTeam | `13 00 12 00` |

## (unnamed table @ 0x0001416ffe68)

`0x0001416ffe68` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGameAttrs | `0a 18 78 00` |
| `PLYR` | mPlayerReports | `01 00 10 00` |

## (unnamed table @ 0x0001416ffe98)

`0x0001416ffe98` - 1 fields

| tag | field | meta |
| --- | --- | --- |
| `BLKS` | mBlocks | `13 00 10 00` |

## (unnamed table @ 0x0001416ffeb0)

`0x0001416ffeb0` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGameAttrs | `0a 18 10 00` |
| `OFFS` | mOffensiveAthleteReports | `01 18 90 00` |
| `PLYR` | mPlayerReports | `01 00 28 00` |

## (unnamed table @ 0x0001416ffef8)

`0x0001416ffef8` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `COUN` | mCountry | `13 18 78 00` |
| `RES ` | mBountyScores | `01 00 10 00` |
| `MILE` | mMilestoneReports | `01 00 10 00` |

## (unnamed table @ 0x0001416fff40)

`0x0001416fff40` - 3 fields

| tag | field | meta |
| --- | --- | --- |
| `CLBS` | mGroupReports | `01 18 c8 00` |
| `GAME` | mGameAttributes | `01 18 10 00` |
| `PLYR` | mPlayerReports | `01 00 60 00` |

## (unnamed table @ 0x0001416fff90)

`0x0001416fff90` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `CLBS` | mGroups | `02 18 50 00` |
| `PLYR` | mPlayers | `02 00 10 00` |

## (unnamed table @ 0x0001416fffc0)

`0x0001416fffc0` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `HITS` | mHits | `13 18 12 00` |
| `SHOT` | mShotsFired | `13 00 10 00` |

## (unnamed table @ 0x0001416ffff0)

`0x0001416ffff0` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `BLKS` | mBlocks | `14 18 20 00` |
| `HITS` | mHits | `14 18 14 00` |
| `MISS` | mMisses | `14 18 1c 00` |
| `REBS` | mRebs | `14 18 24 00` |
| `SCOR` | mScore | `14 18 10 00` |
| `SERV` | mServes | `14 00 18 00` |

## (unnamed table @ 0x000141700080)

`0x000141700080` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `HITS` | mHits | `13 18 10 00` |
| `LOSE` | mLoser | `13 18 18 00` |
| `MISS` | mMisses | `13 18 12 00` |
| `TRCH` | mTorchings | `13 18 14 00` |
| `WIN ` | mWinner | `13 00 16 00` |

## (unnamed table @ 0x0001417000f8)

`0x0001417000f8` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `ISIM` | mIsSim | `14 18 18 00` |
| `LGID` | mLeagueId | `1b 00 10 00` |

## (unnamed table @ 0x000141700130)

`0x000141700130` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `ENTI` | mEntityId | `15 18 10 00` |
| `STAF` | mStatsFlt | `01 18 68 00` |
| `STAI` | mStatsInt | `01 18 18 00` |
| `STAS` | mStatsStr | `01 00 b8 00` |

## (unnamed table @ 0x000141700190)

`0x000141700190` - 10 fields

| tag | field | meta |
| --- | --- | --- |
| `ATMP` | mAttempts | `13 18 1e 00` |
| `EVNT` | mEvent | `15 18 10 00` |
| `IPRE` | mIsProgressionEvent | `0e 18 21 00` |
| `MODC` | mModsCount | `15 18 28 00` |
| `MODU` | mModsUsed | `15 18 24 00` |
| `PBST` | mPb | `0e 18 1c 00` |
| `PRPO` | mProgressionPosition | `11 18 20 00` |
| `SCRE` | mScore | `14 18 14 00` |
| `VEHI` | mVehicle | `15 18 18 00` |
| `WIN ` | mWin | `11 00 1d 00` |

## (unnamed table @ 0x000141700280)

`0x000141700280` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `ATRB` | mStats | `01 18 10 00` |
| `PLYR` | mPlayerReports | `01 00 60 00` |

## (unnamed table @ 0x0001417002b0)

`0x0001417002b0` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `MAP ` | mMapId | `14 18 10 00` |
| `MODE` | mMode | `14 00 14 00` |

## (unnamed table @ 0x0001417002e0)

`0x0001417002e0` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `LEAG` | mLeagueId | `1b 18 10 00` |
| `LEVE` | mLevel | `14 00 18 00` |
| `CHAL` | mChallenge | `15 18 10 00` |
| `CNT ` | mCount | `15 00 14 00` |

## (unnamed table @ 0x000141700340)

`0x000141700340` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGames | `15 18 10 00` |
| `HITS` | mHits | `15 18 18 00` |
| `PF  ` | mPf | `15 18 1c 00` |
| `SERV` | mServes | `15 18 20 00` |
| `TIME` | mTime | `15 00 14 00` |
| `REPS` | mMilestoneReports | `01 00 10 00` |

## (unnamed table @ 0x0001417003e0)

`0x0001417003e0` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `CID ` | mClubId | `17 18 10 00` |
| `LOSS` | mLosses | `13 18 1e 00` |
| `PNTS` | mPoints | `13 18 20 00` |
| `WEPN` | mWeapon | `14 18 18 00` |
| `WINS` | mWins | `13 00 1c 00` |

## (unnamed table @ 0x000141700458)

`0x000141700458` - 2 fields

| tag | field | meta |
| --- | --- | --- |
| `GAME` | mGameAttrs | `0a 18 10 00` |
| `PLYR` | mPlayerReports | `01 00 28 00` |

## (unnamed table @ 0x000141700490)

`0x000141700490` - 6 fields

| tag | field | meta |
| --- | --- | --- |
| `BLOC` | mBlocks | `15 18 1c 00` |
| `GAME` | mGames | `15 18 10 00` |
| `MISS` | mMisses | `15 18 18 00` |
| `REBS` | mRebs | `15 18 20 00` |
| `TIME` | mTime | `15 00 14 00` |
| `ENTS` | mEntries | `02 00 10 00` |

## (unnamed table @ 0x000141705ce0)

`0x000141705ce0` - 17 fields

| tag | field | meta |
| --- | --- | --- |
| `FCRT` | mFailedCriteria | `05 00 10 00` |
| `PDLS` | mCheckoutProducts | `02 18 20 00` |
| `WLNM` | mWalletName | `05 00 10 00` |
| `RID ` | mRowId | `15 00 10 00` |
| `CCDT` | mCreateDate | `05 20 98 00` |
| `CMDT` | mModifiedDate | `05 20 a8 00` |
| `CPDN` | mProductName | `05 20 78 00` |
| `CPJN` | mProjectNumber | `05 20 88 00` |
| `CSER` | mExternalRef | `05 20 48 00` |
| `CSFN` | mFileName | `05 20 38 00` |
| `CSN ` | mName | `05 20 18 00` |
| `CST ` | mType | `05 20 28 00` |
| `CSTA` | mStatus | `05 20 58 00` |
| `CURI` | mUri | `05 20 68 00` |
| `PLST` | mProductAssociationList | `02 18 b8 00` |
| `UID ` | mId | `17 00 10 00` |
| `PDRL` | mProductVector | `02 00 10 00` |

## (unnamed table @ 0x000141705ee0)

`0x000141705ee0` - 13 fields

| tag | field | meta |
| --- | --- | --- |
| `IP  ` | mIp | `15 18 10 00` |
| `MACI` | mMachineId | `17 18 18 00` |
| `PORT` | mPort | `13 00 14 00` |
| `RID ` | mRowId | `15 00 10 00` |
| `COMM` | mComment | `05 20 60 00` |
| `GRP ` | mGroup | `05 20 18 00` |
| `OWNR` | mOwner | `05 20 28 00` |
| `RID ` | mRowId | `15 18 10 00` |
| `SNET` | mSubNet | `0a 00 38 00` |
| `WLNM` | mWalletName | `05 00 10 00` |
| `PPL ` | mPricePointVector | `02 18 18 00` |
| `TCTE` | mIsFree | `0f 00 10 00` |
| `CSTR` | mCode | `05 00 10 00` |

## (unnamed table @ 0x000141706090)

`0x000141706090` - 23 fields

| tag | field | meta |
| --- | --- | --- |
| `MACI` | mMachineId | `17 18 28 00` |
| `NAME` | mHostName | `05 20 10 00` |
| `PORT` | mPort | `13 00 20 00` |
| `WBAL` | mBalance | `05 20 20 00` |
| `WLCR` | mCurrency | `05 00 10 00` |
| `CCAT` | mSrcCatalog | `05 20 10 00` |
| `CPRD` | mSrcProductId | `05 20 20 00` |
| `SPDF` | mIsDefault | `0f 00 30 00` |
| `DLOC` | mDefaultLocale | `15 18 60 00` |
| `FID ` | mFinanceId | `05 20 40 00` |
| `PATT` | mAttribs | `01 18 68 00` |
| `PID ` | mId | `05 20 10 00` |
| `PLFM` | mPlatForm | `05 20 50 00` |
| `PNAM` | mName | `05 20 20 00` |
| `PPP ` | mPricePoints | `0a 18 b8 00` |
| `PTPE` | mType | `05 00 30 00` |
| `PDID` | mProductId | `05 20 10 00` |
| `PDRN` | mQuantity | `15 00 20 00` |
| `NMAP` | mNestedMap | `01 18 78 00` |
| `NUM ` | mNum | `14 18 10 00` |
| `SMAP` | mStringMap | `01 18 28 00` |
| `TEXT` | mText | `05 00 18 00` |
| `NAME` | mEntityNames | `02 00 10 00` |

## (unnamed table @ 0x000141706320)

`0x000141706320` - 8 fields

| tag | field | meta |
| --- | --- | --- |
| `EXIP` | mExternalAddress | `0a 18 30 00` |
| `INIP` | mInternalAddress | `0a 18 10 00` |
| `MACI` | mMachineId | `17 00 50 00` |
| `CLNM` | mCategoryMap | `01 00 10 00` |
| `GRP ` | mGroup | `05 20 18 00` |
| `OWNR` | mOwner | `05 20 28 00` |
| `RID ` | mRowId | `15 18 10 00` |
| `SNET` | mSubNet | `0a 00 38 00` |

## (unnamed table @ 0x000141706430)

`0x000141706430` - 14 fields

| tag | field | meta |
| --- | --- | --- |
| `MACI` | mMachineId | `17 18 30 00` |
| `XDDR` | mXnAddr | `08 10 18 00` |
| `XUID` | mXuid | `17 00 10 00` |
| `MSG ` | mMessage | `05 00 10 00` |
| `CGNM` | mCategoryName | `05 20 20 00` |
| `CLNM` | mCatalogName | `05 20 10 00` |
| `LOC ` | mLocale | `05 20 38 00` |
| `PPSN` | mPageNo | `13 18 32 00` |
| `PPSZ` | mPageSize | `13 00 30 00` |
| `PCTP` | mCurrencyType | `05 20 40 00` |
| `PCUY` | mCurrency | `05 20 30 00` |
| `PP  ` | mPrice | `05 20 20 00` |
| `PPLC` | mLocale | `05 20 50 00` |
| `PPT ` | mPriceType | `05 00 10 00` |

## (unnamed table @ 0x0001417065c0)

`0x0001417065c0` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `PSA ` | mAddress | `05 20 10 00` |
| `PSP ` | mPort | `13 18 20 00` |
| `SNA ` | mSiteName | `05 00 28 00` |
| `CLNM` | mCatalogMap | `01 00 10 00` |

## (unnamed table @ 0x000141706630)

`0x000141706630` - 4 fields

| tag | field | meta |
| --- | --- | --- |
| `MACI` | mMachineId | `17 18 30 00` |
| `PORT` | mPort | `13 18 28 00` |
| `SITE` | mSiteName | `05 20 18 00` |
| `SVID` | mSid | `15 00 10 00` |

## Blaze::DynamicInetFilter::ReplicatedInetFilterReplicationReason

`0x0001417066c8` - 16 fields

| tag | field | meta |
| --- | --- | --- |
| `IP  ` | mIp | `05 20 10 00` |
| `PLEN` | mPrefixLength | `15 00 20 00` |
| `NMPA` | mStringMap | `01 18 28 00` |
| `NUM ` | mNum | `14 18 10 00` |
| `TEXT` | mText | `05 00 18 00` |
| `CGID` | mId | `05 20 10 00` |
| `CTYP` | mType | `05 20 20 00` |
| `DLOC` | mDefaultLocale | `15 18 34 00` |
| `LAMP` | mAttribs | `01 18 80 00` |
| `PCNT` | mProductCount | `15 18 30 00` |
| `SLST` | mSubCategoryList | `02 18 38 00` |
| `TCTE` | mIsTopCategory | `0f 00 78 00` |
| `NLMP` | mPingSiteLatencyByAliasMap | `01 00 10 00` |
| `OID ` | mBlazeObjectId | `0c 00 10 00` |
| `EID ` | mEntityIds | `02 18 18 00` |
| `TYPE` | mBlazeObjectType | `0b 00 10 00` |

## (unnamed table @ 0x000141706860)

`0x000141706860` - 5 fields

| tag | field | meta |
| --- | --- | --- |
| `COMM` | mComment | `05 20 60 00` |
| `GRP ` | mGroup | `05 20 18 00` |
| `OWNR` | mOwner | `05 20 28 00` |
| `RID ` | mRowId | `15 18 10 00` |
| `SNET` | mSubNet | `0a 00 38 00` |

## (unnamed table @ 0x000141706920)

`0x000141706920` - 19 fields

| tag | field | meta |
| --- | --- | --- |
| `ADDR` | mAddress | `09 10 80 00` |
| `NLMP` | mPingSiteLatencyByAliasMap | `01 18 10 00` |
| `NQOS` | mQosData | `0a 00 60 00` |
| `CLNM` | mCatalogName | `05 20 10 00` |
| `LOC ` | mLocale | `05 00 20 00` |
| `NAME` | mEntityName | `05 20 20 00` |
| `TYPE` | mEntityTypeName | `05 00 10 00` |
| `NAME` | mEntityName | `05 00 10 00` |
| `LAMP` | mLocaleAttributeMap | `01 00 10 00` |
| `EID ` | mEntityId | `1b 18 18 00` |
| `TYPE` | mBlazeObjectType | `0b 00 10 00` |
| `CCTP` | mCurrencyType | `05 20 20 00` |
| `CCUY` | mCurrency | `05 20 30 00` |
| `CGID` | mId | `05 20 10 00` |
| `LAMP` | mAttribs | `01 00 40 00` |
| `COMM` | mComment | `05 20 58 00` |
| `GRP ` | mGroup | `05 20 10 00` |
| `OWNR` | mOwner | `05 20 20 00` |
| `SNET` | mSubNet | `0a 00 30 00` |
