module CSE230.Eval where

import qualified CSE230.Types as H
import qualified CSE230.Parse as P
import Data.Map
import Control.Monad.State hiding (when)

{- Build an evaluator for the WHILE Language using 
   the standard library's `State` [monad](http://hackage.haskell.org/packages/archive/mtl/latest/doc/html/Control-Monad-State-Lazy.html#g:2)
   to represent the world-transformer.

   Intuitively, `State s a` is equivalent to the world-transformer `s -> (a, s)`. 
   
   See the above documentation for more details. You can ignore the bits about `StateT` for now.
 -} 


-------------------------------------------------------------------------------
-- | Expression Evaluator 
-------------------------------------------------------------------------------
evalE :: H.Expression -> State H.Store H.Value
evalE e = do 
  s <- get
  return (eval s e)

{- Fill in the implementation of `eval` that
   that takes as input a `Store` and an `Expression` 
   and returns a `Value`.
   
   NOTE: we don't have exceptions yet, so if a variable is not found,
   simply return value `0`.
 -}

store0 :: H.Store
store0 = fromList [("X", H.IntVal 10),("Y", H.IntVal 20)]

-- >>> eval store0 (H.Var "Z")
-- IntVal 0
-- >>> eval store0 (H.Val  (H.IntVal 92))
-- IntVal 92
-- >>> eval store0 (H.Op H.Plus  (H.Var "X") (H.Var "Y"))
-- IntVal 30
-- >>> eval store0 (H.Op H.Minus (H.Var "X") (H.Var "Y"))
-- IntVal (-10)
-- >>> eval store0 (H.Op H.Times (H.Var "X") (H.Var "Y"))
-- IntVal 200
-- >>> eval store0 (H.Op H.Divide (H.Var "Y") (H.Var "X"))
-- IntVal 2
-- >>> eval store0 (H.Op H.Gt (H.Var "Y") (H.Var "X"))
-- BoolVal True
-- >>> eval store0 (H.Op H.Ge (H.Var "Y") (H.Var "X"))
-- BoolVal True
-- >>> eval store0 (H.Op H.Lt (H.Var "Y") (H.Var "X"))
-- BoolVal False
-- >>> eval store0 (H.Op H.Le (H.Var "Y") (H.Var "X"))
-- BoolVal False
--



eval :: H.Store -> H.Expression -> H.Value
eval s (H.Var x)      = error "fill this in"
eval s (H.Val v)      = error "fill this in"
eval s (H.Op o e1 e2) = error "fill this in"

semantics :: H.Bop -> H.Value -> H.Value -> H.Value
semantics H.Plus   = intOp  (+)
semantics H.Minus  = intOp  (-)
semantics H.Times  = intOp  (*)
semantics H.Divide = intOp  (div)
semantics H.Gt     = boolOp (>)
semantics H.Ge     = boolOp (>=)
semantics H.Lt     = boolOp (<)
semantics H.Le     = boolOp (<=)

intOp :: (Int -> Int -> Int) -> H.Value -> H.Value -> H.Value
intOp op (H.IntVal x) (H.IntVal y)  = H.IntVal (x `op` y)
intOp _  _            _             = H.IntVal 0

boolOp :: (Int -> Int -> Bool) -> H.Value -> H.Value -> H.Value
boolOp op (H.IntVal x) (H.IntVal y) = H.BoolVal (x `op` y)
boolOp _  _            _            = H.BoolVal False


-------------------------------------------------------------------------------
-- | Statement Evaluator 
-------------------------------------------------------------------------------

{- Fill in the definition of `evalS` that takes as input a `Statement` 
   and returns a world-transformer that returns a `()`. Here, the 
   world-transformer should in fact update the input store appropriately 
   with the assignments executed in the course of evaluating the `Statement`.

   HINT: The value `put` is of type `Store -> State Store ()`. 
   Thus, to "update" the value of the store with the new store `s'` 
   do `put s`.

   In the `If` case, if `e` evaluates to a non-boolean value, just skip both
   the branches. (We will convert it into a type error in the next homework.)
-}

evalS :: H.Statement -> State H.Store ()
evalS H.Skip             = error "fill this in"
evalS (H.Sequence s1 s2) = error "fill this in"
evalS (H.Assign x e )    = error "fill this in"
evalS (H.If e s1 s2)     = error "fill this in"
evalS w@(H.While e s)    = error "fill this in"

-------------------------------------------------------------------------------
-- | Executor
-------------------------------------------------------------------------------

{- Fill in the implementation of `execS` such that `execS stmt store` 
   returns the new `Store` that results from evaluating the command 
   `stmt` from the world `store`. 

   HINT: You may want to use the library function from `Control.Monad.State` 

     execState :: State s a -> s -> s
 
 -}

-- >>> execS H.w_test empty
-- fromList [("X",IntVal 0),("Y",IntVal 10)]
--
-- >>> execS H.w_fact empty
-- fromList [("F",IntVal 2),("N",IntVal 0),("X",IntVal 1),("Z",IntVal 2)]
--
-- >>> execS H.w_abs empty
-- fromList [("X",IntVal 3)]
--
-- >>> execS H.w_times empty
-- fromList [("X",IntVal 0),("Y",IntVal 3),("Z",IntVal 30)]
--



execS :: H.Statement -> H.Store -> H.Store
execS s = error "fill this in"

-------------------------------------------------------------------------------
-- | Running a Program 
-------------------------------------------------------------------------------

{- When you are done with the `execS`, the following function will 
   "run" a statement starting with the `empty` store (where no 
   variable is initialized). Running the program should print 
   the value of all variables at the end of execution.
 -}

-- >>> run H.w_test
-- Output Store:
-- fromList [("X",IntVal 0),("Y",IntVal 10)]

run :: H.Statement -> IO ()
run stmt = do 
    putStrLn "Output Store:" 
    putStrLn (show (execS stmt empty))

-------------------------------------------------------------------------------
-- | Running a File
-------------------------------------------------------------------------------
runFile :: FilePath -> IO ()
runFile s = do 
  p <- P.parseFile s
  case p of
    Left err   -> print err
    Right stmt -> run stmt

printStore :: H.Store -> IO ()
printStore e = do 
  putStrLn "Environment:"
  putStrLn (show e)

-- When you are done you should see the following at the ghci prompt
--
-- >>> runFile "test/in/test.imp"
-- Output Store:
-- fromList [("X",IntVal 0),("Y",IntVal 10)]

-- >>> runFile "test/in/fact.imp"
-- Output Store:
-- fromList [("F",IntVal 2),("N",IntVal 0),("X",IntVal 1),("Z",IntVal 2)]
