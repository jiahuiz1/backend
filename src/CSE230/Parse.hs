module CSE230.Parse where

import Text.Parsec hiding (State, between)
import Text.Parsec.String
import qualified CSE230.Types as H

{- As you can see, it is rather tedious to write the above tests! 
   They correspond to the code in the files `test.imp` and `fact.imp`. 
   It is rather tedious to have to specify individual programs as Haskell
   values. For this problem, you will use parser combinators to build a parser
   for the WHILE language from the previous problem.
-}

parseFromString :: Parser a -> String -> Either ParseError a 
parseFromString p s = runParser p () "DUMMY" s 

-- >>> parseFromString varP "X45"
-- Right "X"
--

-------------------------------------------------------------------------------
-- | Parsing Constants
-------------------------------------------------------------------------------

-- First, we will write parsers for the `Value` type

valueP :: Parser H.Value
valueP = intP <|> boolP

-- First, fill in the implementation of `intP`. You can assume that the numbers
-- in our language are non-negative.

intP :: Parser H.Value
intP = error "fill this in"

-- Next, define a parser that will accept a particular string `s` as a given value `x`

constP :: String -> a -> Parser a
constP s x = error "fill this in"

-- Use the above to define a parser for boolean values 
-- where `"true"` and `"false"` should be parsed appropriately.

boolP :: Parser H.Value
boolP = error "fill this in"

-- Continue to use the above to parse the binary operators

opP :: Parser H.Bop
opP = error "fill this in"

-------------------------------------------------------------------------------
-- | Parsing Expressions 
-------------------------------------------------------------------------------

-- The following is a parser for variables, which are one-or-more uppercase letters. 

varP :: Parser H.Variable
varP = many1 upper

-- Use the above to write a parser for `Expression` values. Assume that
-- operators are right associative, and they all have the same precedence.

exprP :: Parser H.Expression
exprP   = error "fill this in"

-------------------------------------------------------------------------------
-- | Parsing Statements 
-------------------------------------------------------------------------------

-- Next, use the expression parsers to build a statement parser

statementP :: Parser H.Statement
statementP = error "fill this in"

-- When you are done, we can put the parser and evaluator together 
-- in the end-to-end interpreter function `runFile` in `Main.hs`

-- | Parsing Files 

-------------------------------------------------------------------------------
parseFile :: FilePath -> IO (Either ParseError H.Statement)
-------------------------------------------------------------------------------
-- >>> ((Right H.w_fact) ==) <$> parseFile "test/in/fact.imp"
-- True
-- >>> ((Right H.w_test) == ) <$> parseFile "test/in/test.imp"
-- True
-- >>> ((Right H.w_abs) == ) <$> parseFile "test/in/abs.imp"
-- True
-- >>> ((Right H.w_times) == ) <$> parseFile "test/in/times.imp"
-- True


parseFile f = parseFromFile statementP f
