{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}

module JWT(
    TokenSupport(..),
    Token(..),
    TokenInfo(..),
    Secret(..),
    ISS(..),
    AUD(..),
    createJWT,
    decodeJWT,
    buildSimpleJWT
) where

import Prelude hiding (exp)
import Control.Lens (Lens', view)
import Control.Monad.Reader (MonadReader)
import Control.Monad.Trans (liftIO, MonadIO)
import Crypto.Hash.Algorithms (SHA256)
import Crypto.MAC.HMAC (HMAC(..), hmac)
import Data.Time.Clock.POSIX
import Data.Aeson (FromJSON, ToJSON, decode, encode)
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64.URL as B64
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as BL
import Data.Monoid
import qualified Data.Text as T
import GHC.Generics

newtype Token = Token {getToken :: T.Text}
    deriving (Show, Eq, Generic, ToJSON, FromJSON)

newtype Secret = Secret {getSecret :: String}
    deriving (Show, Eq, Generic, ToJSON, FromJSON)

newtype ISS = ISS {getISS:: String}
    deriving (Show, Eq, Generic, ToJSON, FromJSON)

newtype AUD = AUD {getAUD :: String}
    deriving (Show, Eq, Generic, ToJSON, FromJSON)

data TokenInfo a = TokenInfo {
    iss :: String,
    sub :: String,
    aud :: String,
    exp :: Int,
    iat :: Int,
    payload :: Maybe a
} deriving (Show, Eq, Generic, ToJSON, FromJSON)

class TokenSupport r where
    secret :: Lens' r Secret
    envISS :: Lens' r ISS
    envAUD :: Lens' r AUD

buildSimpleJWT :: (MonadIO m, MonadReader r m, TokenSupport r, ToJSON a) => 
    a -> 
    String -> 
    m Token
buildSimpleJWT payload sub' = do
    iss' <- getISS <$> view envISS
    aud' <- getAUD <$> view envAUD
    now <- liftIO $ round <$> getPOSIXTime
    let ti = TokenInfo {
        iss = iss',
        sub = sub',
        aud = aud',
        exp = now + 36000, -- good for an hour
        iat = now,
        payload = Just payload
    }
    createJWT ti


-- |Create a JWT
createJWT :: (MonadReader r m, TokenSupport r, ToJSON a) => 
    TokenInfo a -> 
    m Token
createJWT inf = do
    secret <- B64.decodeLenient . B.pack . getSecret <$> view secret
    let header = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
    let payload = B.filter (/= '=') . B64.encode . BL.toStrict $ encode inf
    let sig = hmac' secret $ header<>"."<> payload
    return . Token . T.pack . B.unpack $ header<>"."<>payload<>"."<>sig

-- |Decode and verify a JWT, decoding app_metadata to the specified type
decodeJWT :: (MonadReader r m, TokenSupport r, FromJSON a) => 
    Token -> 
    m (Maybe (TokenInfo a))
decodeJWT tok = do
    secret <- B64.decodeLenient . B.pack . getSecret <$> view secret
    case T.splitOn "." (getToken tok) of
        [header,body,sig] -> return $ do
            let sig' = T.pack . B.unpack . hmac' secret . B.pack $ T.unpack (header<>"."<>body)
            if sig' == sig
              then decode (BL.fromStrict . B64.decodeLenient . B.pack $ T.unpack body)
              else Nothing
        _ -> return Nothing

hmac' :: B.ByteString -> B.ByteString -> B.ByteString
hmac' key message = B.takeWhile (/='=') . B64.encode . fst . B16.decode . B.pack . show $ hmacGetDigest (hmac key message :: HMAC SHA256)
